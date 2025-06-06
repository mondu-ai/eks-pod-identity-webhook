# EKS Pod Identity Webhook

A Helm chart for deploying the EKS Pod Identity Webhook.

## Installing the Chart

Add the Mondu AI Helm repository:

```bash
helm repo add mondu-ai https://mondu-ai.github.io/eks-pod-identity-webhook
helm repo update
```

Install or upgrade the chart:

```bash
helm upgrade --install eks-pod-identity-webhook \
  mondu-ai/eks-pod-identity-webhook \
  --namespace aws-pod-identity-webhook
```

## Uninstalling the Chart

To uninstall/delete the release:

```bash
helm uninstall eks-pod-identity-webhook --namespace aws-pod-identity-webhook
```

## Configuration

The following table lists the most commonly used parameters of the chart. See
`values.yaml` for the full list.

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of webhook replicas | `3` |
| `image.repository` | Container image repository | `ghcr.io/mondu-ai/eks-pod-identity-webhook` |
| `image.tag` | Image tag | `latest` |
| `serviceAccount.create` | Create a service account | `true` |
| `serviceAccount.name` | Service account name | `aws-pod-identity-webhook-sa` |
| `certManager.enabled` | Manage certificates with cert-manager | `true` |
| `existingTLSSecret` | Use an existing TLS secret | `""` |
| `service.port` | Webhook service port | `443` |
| `env.AWS_REGION` | Default AWS region | `us-east-1` |


