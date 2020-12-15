package cmd

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/linkerd/linkerd2/controller/gen/public"
	"github.com/linkerd/linkerd2/pkg/healthcheck"
	"github.com/linkerd/linkerd2/pkg/k8s"
	"github.com/linkerd/linkerd2/pkg/multicluster"
	"github.com/linkerd/linkerd2/pkg/servicemirror"
	"github.com/linkerd/linkerd2/pkg/tls"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	// multiclusterExtensionName is the name of the multicluster extension
	multiclusterExtensionName = "linkerd-multicluster"

	// linkerdMulticlusterExtensionCheck adds checks related to the multicluster extension
	linkerdMulticlusterExtensionCheck healthcheck.CategoryID = multiclusterExtensionName

	linkerdServiceMirrorServiceAccountName = "linkerd-service-mirror-%s"
	linkerdServiceMirrorComponentName      = "service-mirror"
	linkerdServiceMirrorClusterRoleName    = "linkerd-service-mirror-access-local-resources-%s"
	linkerdServiceMirrorRoleName           = "linkerd-service-mirror-read-remote-creds-%s"
)

var multiclusterNamespace string

type checkOptions struct {
	wait   time.Duration
	output string
}

func newCheckOptions() *checkOptions {
	return &checkOptions{
		wait:   300 * time.Second,
		output: healthcheck.TableOutput,
	}
}

func (options *checkOptions) validate() error {
	if options.output != healthcheck.TableOutput && options.output != healthcheck.JSONOutput {
		return fmt.Errorf("Invalid output type '%s'. Supported output types are: %s, %s", options.output, healthcheck.JSONOutput, healthcheck.TableOutput)
	}
	return nil
}

func newCmdCheck() *cobra.Command {
	options := newCheckOptions()
	cmd := &cobra.Command{
		Use:   "check [flags]",
		Args:  cobra.NoArgs,
		Short: "Check the multicluster extension for potential problems",
		Long: `Check the multicluster extension for potential problems.

The check command will perform a series of checks to validate that the
multicluster extension is configured correctly. If the command encounters a
failure it will print additional information about the failure and exit with a
non-zero exit code.`,
		Example: `  # Check that the multicluster extension is configured correctly
  linkerd multicluster check`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Get the multicluster extension namespace
			kubeAPI, err := k8s.NewAPI(kubeconfigPath, kubeContext, impersonate, impersonateGroup, 0)
			ns, err := kubeAPI.GetNamespaceWithExtensionLabel(context.Background(), multiclusterExtensionName)
			if err != nil {
				err = fmt.Errorf("%w; install by running `linkerd multicluster install | kubectl apply -f -`", err)
				fmt.Fprintln(os.Stderr, err.Error())
				os.Exit(1)
			}
			multiclusterNamespace = ns.Name
			return configureAndRunChecks(stdout, stderr, options)
		},
	}
	cmd.PersistentFlags().StringVarP(&options.output, "output", "o", options.output, "Output format. One of: basic, json")
	cmd.PersistentFlags().DurationVar(&options.wait, "wait", options.wait, "Maximum allowed time for all tests to pass")
	return cmd
}

func configureAndRunChecks(wout io.Writer, werr io.Writer, options *checkOptions) error {
	err := options.validate()
	if err != nil {
		return fmt.Errorf("Validation error when executing check command: %v", err)
	}
	checks := []healthcheck.CategoryID{
		linkerdMulticlusterExtensionCheck,
	}
	hc := healthcheck.NewHealthChecker(checks, &healthcheck.Options{
		ControlPlaneNamespace: controlPlaneNamespace,
		KubeConfig:            kubeconfigPath,
		KubeContext:           kubeContext,
		Impersonate:           impersonate,
		ImpersonateGroup:      impersonateGroup,
		APIAddr:               apiAddr,
		RetryDeadline:         time.Now().Add(options.wait),
		MultiCluster:          false,
	})
	category, err := multiclusterCategory(hc)
	if err != nil {
		return err
	}
	hc.AppendCategories(*category)
	success := healthcheck.RunChecks(wout, werr, hc, options.output)
	if !success {
		os.Exit(1)
	}
	return nil
}

func multiclusterCategory(hc *healthcheck.HealthChecker) (*healthcheck.Category, error) {
	kubeAPI, err := k8s.NewAPI(hc.KubeConfig, hc.KubeContext, hc.Impersonate, hc.ImpersonateGroup, 0)
	if err != nil {
		return nil, err
	}
	var links []multicluster.Link
	checkers := []healthcheck.Checker{}
	// Link checks
	checkers = append(checkers,
		*healthcheck.NewChecker("Link CRD exists", "l5d-multicluster-link-crd-exists", true, false, time.Time{}, false).
			WithCheck(func(ctx context.Context) error { return checkLinkCRD(ctx, kubeAPI) }))
	checkers = append(checkers,
		*healthcheck.NewChecker("Link resources are valid", "l5d-multicluster-links-are-valid", true, false, time.Time{}, false).
			WithCheck(func(ctx context.Context) error { return checkLinks(ctx, kubeAPI, links) }))
	// Target cluster access checks
	checkers = append(checkers,
		*healthcheck.NewChecker("remote cluster access credentials are valid", "l5d-smc-target-clusters-access", false, false, time.Time{}, false).
			WithCheck(func(ctx context.Context) error { return checkRemoteClusterConnectivity(ctx, kubeAPI, links) }))
	checkers = append(checkers,
		*healthcheck.NewChecker("clusters share trust anchors", "l5d-multicluster-clusters-share-anchors", false, false, time.Time{}, false).
			WithCheck(func(ctx context.Context) error {
				localAnchors, err := tls.DecodePEMCertificates(hc.LinkerdConfigGlobal().IdentityTrustAnchorsPEM)
				if err != nil {
					return fmt.Errorf("Cannot parse source trust anchors: %s", err)
				}
				return checkRemoteClusterAnchors(ctx, kubeAPI, links, localAnchors)
			}))
	checkers = append(checkers,
		*healthcheck.NewChecker("service mirror controller has required permissions", "l5d-multicluster-source-rbac-correct", false, false, time.Time{}, false).
			WithCheck(func(ctx context.Context) error {
				return checkServiceMirrorLocalRBAC(ctx, kubeAPI, links)
			}))
	checkers = append(checkers,
		*healthcheck.NewChecker("service mirror controllers are running", "l5d-multicluster-service-mirror-running", false, false, hc.RetryDeadline, true).
			WithCheck(func(ctx context.Context) error {
				return checkServiceMirrorController(ctx, kubeAPI, links)
			}))
	checkers = append(checkers,
		*healthcheck.NewChecker("all gateway mirrors are healthy", "l5d-multicluster-gateways-endpoints", false, false, time.Time{}, false).
			WithCheck(func(ctx context.Context) error {
				return checkIfGatewayMirrorsHaveEndpoints(ctx, kubeAPI, links, hc)
			}))
	checkers = append(checkers,
		*healthcheck.NewChecker("all mirror services have endpoints", "l5d-multicluster-services-endpoints", false, false, time.Time{}, false).
			WithCheck(func(ctx context.Context) error {
				return checkIfMirrorServicesHaveEndpoints(ctx, kubeAPI)
			}))
	checkers = append(checkers,
		*healthcheck.NewChecker("all mirror services are part of a Link", "l5d-multicluster-orphaned-services", false, true, time.Time{}, false).
			WithCheck(func(ctx context.Context) error {
				return checkForOrphanedServices(ctx, kubeAPI)
			}))
	return healthcheck.NewCategory(linkerdMulticlusterExtensionCheck, checkers, true), nil
}

func checkLinkCRD(ctx context.Context, kubeAPI *k8s.KubernetesAPI) error {
	err := linkAccess(ctx, kubeAPI.Interface)
	if err != nil {
		return fmt.Errorf("multicluster.linkerd.io/Link CRD is missing: %s", err)
	}
	return nil
}

func linkAccess(ctx context.Context, k8sClient kubernetes.Interface) error {
	res, err := k8sClient.Discovery().ServerResourcesForGroupVersion(k8s.LinkAPIGroupVersion)
	if err != nil {
		return err
	}
	if res.GroupVersion == k8s.LinkAPIGroupVersion {
		for _, apiRes := range res.APIResources {
			if apiRes.Kind == k8s.LinkKind {
				return k8s.ResourceAuthz(ctx, k8sClient, "", "list", k8s.LinkAPIGroup, k8s.LinkAPIVersion, "links", "")
			}
		}
	}
	return errors.New("Link CRD not found")
}

func checkLinks(ctx context.Context, kubeAPI *k8s.KubernetesAPI, links []multicluster.Link) error {
	var err error
	links, err = multicluster.GetLinks(ctx, kubeAPI.DynamicClient)
	if err != nil {
		return err
	}
	linkNames := []string{}
	for _, l := range links {
		linkNames = append(linkNames, fmt.Sprintf("\t* %s", l.TargetClusterName))
	}
	return &healthcheck.VerboseSuccess{Message: strings.Join(linkNames, "\n")}
}

func checkRemoteClusterConnectivity(ctx context.Context, kubeAPI *k8s.KubernetesAPI, links []multicluster.Link) error {
	errors := []error{}
	linkNames := []string{}
	for _, link := range links {
		// Load the credentials secret
		secret, err := kubeAPI.Interface.CoreV1().Secrets(link.Namespace).Get(ctx, link.ClusterCredentialsSecret, metav1.GetOptions{})
		if err != nil {
			errors = append(errors, fmt.Errorf("* secret: [%s/%s]: %s", link.Namespace, link.ClusterCredentialsSecret, err))
			continue
		}
		config, err := servicemirror.ParseRemoteClusterSecret(secret)
		if err != nil {
			errors = append(errors, fmt.Errorf("* secret: [%s/%s]: could not parse config secret: %s", secret.Namespace, secret.Name, err))
			continue
		}
		clientConfig, err := clientcmd.RESTConfigFromKubeConfig(config)
		if err != nil {
			errors = append(errors, fmt.Errorf("* secret: [%s/%s] cluster: [%s]: unable to parse api config: %s", secret.Namespace, secret.Name, link.TargetClusterName, err))
			continue
		}
		remoteAPI, err := k8s.NewAPIForConfig(clientConfig, "", []string{}, healthcheck.RequestTimeout)
		if err != nil {
			errors = append(errors, fmt.Errorf("* secret: [%s/%s] cluster: [%s]: could not instantiate api for target cluster: %s", secret.Namespace, secret.Name, link.TargetClusterName, err))
			continue
		}
		// We use this call just to check connectivity.
		_, err = remoteAPI.Discovery().ServerVersion()
		if err != nil {
			errors = append(errors, fmt.Errorf("* failed to connect to API for cluster: [%s]: %s", link.TargetClusterName, err))
			continue
		}
		verbs := []string{"get", "list", "watch"}
		for _, verb := range verbs {
			if err := healthcheck.CheckCanPerformAction(ctx, remoteAPI, verb, corev1.NamespaceAll, "", "v1", "services"); err != nil {
				errors = append(errors, fmt.Errorf("* missing service permission [%s] for cluster [%s]: %s", verb, link.TargetClusterName, err))
			}
		}
		linkNames = append(linkNames, fmt.Sprintf("\t* %s", link.TargetClusterName))
	}
	if len(errors) > 0 {
		return joinErrors(errors, 2)
	}
	if len(linkNames) == 0 {
		return &healthcheck.SkipError{Reason: "no links"}
	}
	return &healthcheck.VerboseSuccess{Message: strings.Join(linkNames, "\n")}
}

func checkRemoteClusterAnchors(ctx context.Context, kubeAPI *k8s.KubernetesAPI, links []multicluster.Link, localAnchors []*x509.Certificate) error {
	errors := []string{}
	linkNames := []string{}
	for _, link := range links {
		// Load the credentials secret
		secret, err := kubeAPI.Interface.CoreV1().Secrets(link.Namespace).Get(ctx, link.ClusterCredentialsSecret, metav1.GetOptions{})
		if err != nil {
			errors = append(errors, fmt.Sprintf("* secret: [%s/%s]: %s", link.Namespace, link.ClusterCredentialsSecret, err))
			continue
		}
		config, err := servicemirror.ParseRemoteClusterSecret(secret)
		if err != nil {
			errors = append(errors, fmt.Sprintf("* secret: [%s/%s]: could not parse config secret: %s", secret.Namespace, secret.Name, err))
			continue
		}
		clientConfig, err := clientcmd.RESTConfigFromKubeConfig(config)
		if err != nil {
			errors = append(errors, fmt.Sprintf("* secret: [%s/%s] cluster: [%s]: unable to parse api config: %s", secret.Namespace, secret.Name, link.TargetClusterName, err))
			continue
		}
		remoteAPI, err := k8s.NewAPIForConfig(clientConfig, "", []string{}, healthcheck.RequestTimeout)
		if err != nil {
			errors = append(errors, fmt.Sprintf("* secret: [%s/%s] cluster: [%s]: could not instantiate api for target cluster: %s", secret.Namespace, secret.Name, link.TargetClusterName, err))
			continue
		}
		_, values, err := healthcheck.FetchCurrentConfiguration(ctx, remoteAPI, link.TargetClusterLinkerdNamespace)
		if err != nil {
			errors = append(errors, fmt.Sprintf("* %s: unable to fetch anchors: %s", link.TargetClusterName, err))
			continue
		}
		remoteAnchors, err := tls.DecodePEMCertificates(values.GetGlobal().IdentityTrustAnchorsPEM)
		if err != nil {
			errors = append(errors, fmt.Sprintf("* %s: cannot parse trust anchors", link.TargetClusterName))
			continue
		}
		// we fail early if the lens are not the same. If they are the
		// same, we can only compare certs one way and be sure we have
		// identical anchors
		if len(remoteAnchors) != len(localAnchors) {
			errors = append(errors, fmt.Sprintf("* %s", link.TargetClusterName))
			continue
		}
		localAnchorsMap := make(map[string]*x509.Certificate)
		for _, c := range localAnchors {
			localAnchorsMap[string(c.Signature)] = c
		}
		for _, remote := range remoteAnchors {
			local, ok := localAnchorsMap[string(remote.Signature)]
			if !ok || !local.Equal(remote) {
				errors = append(errors, fmt.Sprintf("* %s", link.TargetClusterName))
				break
			}
		}
		linkNames = append(linkNames, fmt.Sprintf("\t* %s", link.TargetClusterName))
	}
	if len(errors) > 0 {
		return fmt.Errorf("Problematic clusters:\n    %s", strings.Join(errors, "\n    "))
	}
	if len(linkNames) == 0 {
		return &healthcheck.SkipError{Reason: "no links"}
	}
	return &healthcheck.VerboseSuccess{Message: strings.Join(linkNames, "\n")}
}

func checkServiceMirrorLocalRBAC(ctx context.Context, kubeAPI *k8s.KubernetesAPI, links []multicluster.Link) error {
	linkNames := []string{}
	errors := []string{}
	for _, link := range links {
		err := healthcheck.CheckServiceAccounts(
			ctx,
			kubeAPI,
			[]string{fmt.Sprintf(linkerdServiceMirrorServiceAccountName, link.TargetClusterName)},
			link.Namespace,
			serviceMirrorComponentsSelector(link.TargetClusterName),
		)
		if err != nil {
			errors = append(errors, err.Error())
		}
		err = healthcheck.CheckClusterRoles(
			ctx,
			kubeAPI,
			true,
			[]string{fmt.Sprintf(linkerdServiceMirrorClusterRoleName, link.TargetClusterName)},
			serviceMirrorComponentsSelector(link.TargetClusterName),
		)
		if err != nil {
			errors = append(errors, err.Error())
		}
		err = healthcheck.CheckClusterRoleBindings(
			ctx,
			kubeAPI,
			true,
			[]string{fmt.Sprintf(linkerdServiceMirrorClusterRoleName, link.TargetClusterName)},
			serviceMirrorComponentsSelector(link.TargetClusterName),
		)
		if err != nil {
			errors = append(errors, err.Error())
		}
		err = healthcheck.CheckRoles(
			ctx,
			kubeAPI,
			true,
			link.Namespace,
			[]string{fmt.Sprintf(linkerdServiceMirrorRoleName, link.TargetClusterName)},
			serviceMirrorComponentsSelector(link.TargetClusterName),
		)
		if err != nil {
			errors = append(errors, err.Error())
		}
		err = healthcheck.CheckRoleBindings(
			ctx,
			kubeAPI,
			true,
			link.Namespace,
			[]string{fmt.Sprintf(linkerdServiceMirrorRoleName, link.TargetClusterName)},
			serviceMirrorComponentsSelector(link.TargetClusterName),
		)
		if err != nil {
			errors = append(errors, err.Error())
		}
		linkNames = append(linkNames, fmt.Sprintf("\t* %s", link.TargetClusterName))
	}
	if len(errors) > 0 {
		return fmt.Errorf(strings.Join(errors, "\n"))
	}
	if len(linkNames) == 0 {
		return &healthcheck.SkipError{Reason: "no links"}
	}
	return &healthcheck.VerboseSuccess{Message: strings.Join(linkNames, "\n")}
}

func checkServiceMirrorController(ctx context.Context, kubeAPI *k8s.KubernetesAPI, links []multicluster.Link) error {
	errors := []error{}
	clusterNames := []string{}
	for _, link := range links {
		options := metav1.ListOptions{
			LabelSelector: serviceMirrorComponentsSelector(link.TargetClusterName),
		}
		result, err := kubeAPI.AppsV1().Deployments(corev1.NamespaceAll).List(ctx, options)
		if err != nil {
			return err
		}
		if len(result.Items) > 1 {
			errors = append(errors, fmt.Errorf("* too many service mirror controller deployments for Link %s", link.TargetClusterName))
			continue
		}
		if len(result.Items) == 0 {
			errors = append(errors, fmt.Errorf("* no service mirror controller deployment for Link %s", link.TargetClusterName))
			continue
		}
		controller := result.Items[0]
		if controller.Status.AvailableReplicas < 1 {
			errors = append(errors, fmt.Errorf("* service mirror controller is not available: %s/%s", controller.Namespace, controller.Name))
			continue
		}
		clusterNames = append(clusterNames, fmt.Sprintf("\t* %s", link.TargetClusterName))
	}
	if len(errors) > 0 {
		return joinErrors(errors, 2)
	}
	if len(clusterNames) == 0 {
		return &healthcheck.SkipError{Reason: "no links"}
	}
	return &healthcheck.VerboseSuccess{Message: strings.Join(clusterNames, "\n")}
}

func checkIfGatewayMirrorsHaveEndpoints(ctx context.Context, kubeAPI *k8s.KubernetesAPI, links []multicluster.Link, hc *healthcheck.HealthChecker) error {
	linkNames := []string{}
	errors := []error{}
	for _, link := range links {
		selector := metav1.ListOptions{LabelSelector: fmt.Sprintf("%s,%s=%s", k8s.MirroredGatewayLabel, k8s.RemoteClusterNameLabel, link.TargetClusterName)}
		gatewayMirrors, err := kubeAPI.CoreV1().Services(metav1.NamespaceAll).List(ctx, selector)
		if err != nil {
			errors = append(errors, err)
			continue
		}
		if len(gatewayMirrors.Items) != 1 {
			errors = append(errors, fmt.Errorf("wrong number (%d) of probe gateways for target cluster %s", len(gatewayMirrors.Items), link.TargetClusterName))
			continue
		}
		svc := gatewayMirrors.Items[0]
		// Check if there is a relevant end-point
		endpoints, err := kubeAPI.CoreV1().Endpoints(svc.Namespace).Get(ctx, svc.Name, metav1.GetOptions{})
		if err != nil || len(endpoints.Subsets) == 0 {
			errors = append(errors, fmt.Errorf("%s.%s mirrored from cluster [%s] has no endpoints", svc.Name, svc.Namespace, svc.Labels[k8s.RemoteClusterNameLabel]))
			continue
		}
		// Check gateway liveness according to probes
		req := public.GatewaysRequest{
			TimeWindow:        "1m",
			RemoteClusterName: link.TargetClusterName,
		}
		rsp, err := hc.Gateways(ctx, &req)
		if err != nil {
			errors = append(errors, fmt.Errorf("failed to fetch gateway metrics for %s.%s: %s", svc.Name, svc.Namespace, err))
			continue
		}
		table := rsp.GetOk().GetGatewaysTable()
		if table == nil {
			errors = append(errors, fmt.Errorf("failed to fetch gateway metrics for %s.%s: %s", svc.Name, svc.Namespace, rsp.GetError().GetError()))
			continue
		}
		if len(table.Rows) != 1 {
			errors = append(errors, fmt.Errorf("wrong number of (%d) gateway metrics entries for %s.%s", len(table.Rows), svc.Name, svc.Namespace))
			continue
		}
		row := table.Rows[0]
		if !row.Alive {
			errors = append(errors, fmt.Errorf("liveness checks failed for %s", link.TargetClusterName))
			continue
		}
		linkNames = append(linkNames, fmt.Sprintf("\t* %s", link.TargetClusterName))
	}
	if len(errors) > 0 {
		return joinErrors(errors, 1)
	}
	if len(linkNames) == 0 {
		return &healthcheck.SkipError{Reason: "no links"}
	}
	return &healthcheck.VerboseSuccess{Message: strings.Join(linkNames, "\n")}
}

func checkIfMirrorServicesHaveEndpoints(ctx context.Context, kubeAPI *k8s.KubernetesAPI) error {
	var servicesWithNoEndpoints []string
	selector := fmt.Sprintf("%s, !%s", k8s.MirroredResourceLabel, k8s.MirroredGatewayLabel)
	mirrorServices, err := kubeAPI.CoreV1().Services(metav1.NamespaceAll).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return err
	}
	for _, svc := range mirrorServices.Items {
		// Check if there is a relevant end-point
		endpoint, err := kubeAPI.CoreV1().Endpoints(svc.Namespace).Get(ctx, svc.Name, metav1.GetOptions{})
		if err != nil || len(endpoint.Subsets) == 0 {
			servicesWithNoEndpoints = append(servicesWithNoEndpoints, fmt.Sprintf("%s.%s mirrored from cluster [%s]", svc.Name, svc.Namespace, svc.Labels[k8s.RemoteClusterNameLabel]))
		}
	}
	if len(servicesWithNoEndpoints) > 0 {
		return fmt.Errorf("Some mirror services do not have endpoints:\n    %s", strings.Join(servicesWithNoEndpoints, "\n    "))
	}
	if len(mirrorServices.Items) == 0 {
		return &healthcheck.SkipError{Reason: "no mirror services"}
	}
	return nil
}

func checkForOrphanedServices(ctx context.Context, kubeAPI *k8s.KubernetesAPI) error {
	errors := []error{}
	selector := fmt.Sprintf("%s, !%s", k8s.MirroredResourceLabel, k8s.MirroredGatewayLabel)
	mirrorServices, err := kubeAPI.CoreV1().Services(metav1.NamespaceAll).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return err
	}
	links, err := multicluster.GetLinks(ctx, kubeAPI.DynamicClient)
	if err != nil {
		return err
	}
	for _, svc := range mirrorServices.Items {
		targetCluster := svc.Labels[k8s.RemoteClusterNameLabel]
		hasLink := false
		for _, link := range links {
			if link.TargetClusterName == targetCluster {
				hasLink = true
				break
			}
		}
		if !hasLink {
			errors = append(errors, fmt.Errorf("mirror service %s.%s is not part of any Link", svc.Name, svc.Namespace))
		}
	}
	if len(mirrorServices.Items) == 0 {
		return &healthcheck.SkipError{Reason: "no mirror services"}
	}
	if len(errors) > 0 {
		return joinErrors(errors, 1)
	}
	return nil
}

func joinErrors(errs []error, tabDepth int) error {
	indent := strings.Repeat("    ", tabDepth)
	errStrings := []string{}
	for _, err := range errs {
		errStrings = append(errStrings, indent+err.Error())
	}
	return errors.New(strings.Join(errStrings, "\n"))
}

func serviceMirrorComponentsSelector(targetCluster string) string {
	return fmt.Sprintf("%s=%s,%s=%s",
		k8s.ControllerComponentLabel, linkerdServiceMirrorComponentName,
		k8s.RemoteClusterNameLabel, targetCluster)
}
