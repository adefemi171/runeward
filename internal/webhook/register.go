package webhook

import (
	"context"
	"fmt"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// configName is the shared name of the self-registered webhook configurations.
const configName = "runeward.dev"

// Register upserts the validating and mutating webhook configurations that
// route Sandbox/Fleet admission to the given Service. caPEM is published as
// each webhook's caBundle so the API server trusts the self-signed serving
// certificate.
func Register(ctx context.Context, clientset kubernetes.Interface, caPEM []byte, service, namespace string) error {
	if err := registerValidating(ctx, clientset, caPEM, service, namespace); err != nil {
		return fmt.Errorf("register validating webhook: %w", err)
	}
	if err := registerMutating(ctx, clientset, caPEM, service, namespace); err != nil {
		return fmt.Errorf("register mutating webhook: %w", err)
	}
	return nil
}

// webhookRules matches CREATE/UPDATE on the namespaced Sandbox/Fleet and
// cluster-scoped ClusterSandbox/ClusterFleet resources.
func webhookRules() []admissionregistrationv1.RuleWithOperations {
	namespaced := admissionregistrationv1.NamespacedScope
	cluster := admissionregistrationv1.ClusterScope
	ops := []admissionregistrationv1.OperationType{
		admissionregistrationv1.Create,
		admissionregistrationv1.Update,
	}
	return []admissionregistrationv1.RuleWithOperations{
		{
			Operations: ops,
			Rule: admissionregistrationv1.Rule{
				APIGroups:   []string{"runeward.dev"},
				APIVersions: []string{"v1alpha1"},
				Resources:   []string{"sandboxes", "fleets"},
				Scope:       &namespaced,
			},
		},
		{
			Operations: ops,
			Rule: admissionregistrationv1.Rule{
				APIGroups:   []string{"runeward.dev"},
				APIVersions: []string{"v1alpha1"},
				Resources:   []string{"clustersandboxes", "clusterfleets"},
				Scope:       &cluster,
			},
		},
	}
}

func clientConfig(caPEM []byte, service, namespace, path string) admissionregistrationv1.WebhookClientConfig {
	p := path
	return admissionregistrationv1.WebhookClientConfig{
		Service: &admissionregistrationv1.ServiceReference{
			Name:      service,
			Namespace: namespace,
			Path:      &p,
		},
		CABundle: caPEM,
	}
}

func registerValidating(ctx context.Context, clientset kubernetes.Interface, caPEM []byte, service, namespace string) error {
	fail := admissionregistrationv1.Ignore
	sideEffects := admissionregistrationv1.SideEffectClassNone
	desired := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name:   configName,
			Labels: map[string]string{"app.kubernetes.io/managed-by": "runeward"},
		},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{{
			Name:                    "validate.runeward.dev",
			ClientConfig:            clientConfig(caPEM, service, namespace, "/validate"),
			Rules:                   webhookRules(),
			FailurePolicy:           &fail,
			SideEffects:             &sideEffects,
			AdmissionReviewVersions: []string{"v1"},
		}},
	}

	api := clientset.AdmissionregistrationV1().ValidatingWebhookConfigurations()
	existing, err := api.Get(ctx, configName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = api.Create(ctx, desired, metav1.CreateOptions{})
		return err
	}
	if err != nil {
		return err
	}
	desired.ResourceVersion = existing.ResourceVersion
	_, err = api.Update(ctx, desired, metav1.UpdateOptions{})
	return err
}

func registerMutating(ctx context.Context, clientset kubernetes.Interface, caPEM []byte, service, namespace string) error {
	fail := admissionregistrationv1.Ignore
	sideEffects := admissionregistrationv1.SideEffectClassNone
	reinvocation := admissionregistrationv1.NeverReinvocationPolicy
	desired := &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name:   configName,
			Labels: map[string]string{"app.kubernetes.io/managed-by": "runeward"},
		},
		Webhooks: []admissionregistrationv1.MutatingWebhook{{
			Name:                    "mutate.runeward.dev",
			ClientConfig:            clientConfig(caPEM, service, namespace, "/mutate"),
			Rules:                   webhookRules(),
			FailurePolicy:           &fail,
			SideEffects:             &sideEffects,
			AdmissionReviewVersions: []string{"v1"},
			ReinvocationPolicy:      &reinvocation,
		}},
	}

	api := clientset.AdmissionregistrationV1().MutatingWebhookConfigurations()
	existing, err := api.Get(ctx, configName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = api.Create(ctx, desired, metav1.CreateOptions{})
		return err
	}
	if err != nil {
		return err
	}
	desired.ResourceVersion = existing.ResourceVersion
	_, err = api.Update(ctx, desired, metav1.UpdateOptions{})
	return err
}
