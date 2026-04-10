# Generator Labs Agent

![CI](https://github.com/generator-labs/agent/actions/workflows/ci.yml/badge.svg)
![Publish](https://github.com/generator-labs/agent/actions/workflows/publish.yml/badge.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![C++23](https://img.shields.io/badge/C%2B%2B-23-blue.svg)
![Platform](https://img.shields.io/badge/platform-amd64%20%7C%20arm64-lightgrey.svg)

A lightweight monitoring agent that runs inside your network to monitor internal services that are not directly accessible from the internet. The agent polls the Generator Labs platform for monitoring tasks, executes checks locally, and reports results back.

Currently, the agent supports SSL/TLS certificate validation across HTTPS, SMTP(S), IMAP(S), POP3(S), FTP(S), LDAP(S), LMTP, MySQL, PostgreSQL, and SIP, including STARTTLS negotiation.

## How It Works

The agent uses an outbound-only communication model and requires no inbound ports or firewall rules. On startup, it authenticates with the Generator Labs platform, then enters a polling loop to check for assigned monitoring tasks. Each task is executed locally within your network, and the results are reported back to the platform over HTTPS. In `PERSISTENT` mode the agent polls continuously; in `SINGLE` mode it processes available tasks once and exits.

## Supported Platforms

The agent image is published as a multi-architecture image supporting:

- **linux/amd64** (x86_64)
- **linux/arm64** (Apple Silicon, AWS Graviton, Raspberry Pi 4+)

Docker automatically selects the correct architecture when pulling the image.

## Requirements

- A container runtime (Docker, Kubernetes, or AWS ECS)
- Network access from the agent to the services you want to monitor
- Outbound HTTPS access to `agent.generatorlabs.com`
- An agent SID and token from the [Generator Labs management portal](https://generatorlabs.com)

## Configuration

### Required Environment Variables

| Variable | Description |
|----------|-------------|
| `GENERATOR_AGENT_SID` | The unique identifier for this agent (34 characters) |
| `GENERATOR_AGENT_TOKEN` | The authentication token for this agent (64 characters) |

Both values are available from the Generator Labs management portal.

### Optional Environment Variables

| Variable | Description |
|----------|-------------|
| `GENERATOR_AGENT_MODE` | Set to `SINGLE` to run once and exit, or `PERSISTENT` (default) to run continuously. Use `SINGLE` when running the agent as a scheduled task (e.g. cron) rather than a long-lived service. |
| `GENERATOR_AGENT_URL` | Override the default platform endpoint URL. Intended for development and testing only. |
| `GENERATOR_AGENT_PROXY` | HTTP proxy URL for agent-to-platform communication. This proxy is only used for API requests, not for local monitoring checks. |

## Deployment

> **Tip:** The examples below use the `latest` tag for simplicity. For production deployments, pin to a specific version tag (e.g. `ghcr.io/generator-labs/agent:1.0`) to avoid unexpected changes during container restarts or redeployments.

### Docker Compose

Create a `.env` file with your agent credentials:

```
GENERATOR_AGENT_SID=your-agent-sid-here
GENERATOR_AGENT_TOKEN=your-agent-token-here
```

Create a `compose.yaml`:

```yaml
services:
  agent:
    image: ghcr.io/generator-labs/agent:latest
    networks:
      - agent-network
    tty: false
    stdin_open: false
    restart: unless-stopped
    env_file:
      - .env
    healthcheck:
      test: ["CMD-SHELL", "pgrep agent || exit 1"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s

networks:
  agent-network:
    enable_ipv6: true
```

Start the agent:

```bash
docker compose up -d
```

Verify it's running:

```bash
docker compose ps
```

### Kubernetes

Create a Secret with your agent credentials:

```bash
kubectl create secret generic generator-agent \
  --from-literal=GENERATOR_AGENT_SID=your-agent-sid-here \
  --from-literal=GENERATOR_AGENT_TOKEN=your-agent-token-here
```

Deploy the agent:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: generator-agent
  labels:
    app: generator-agent
spec:
  replicas: 1
  selector:
    matchLabels:
      app: generator-agent
  template:
    metadata:
      labels:
        app: generator-agent
    spec:
      containers:
        - name: agent
          image: ghcr.io/generator-labs/agent:latest
          envFrom:
            - secretRef:
                name: generator-agent
          livenessProbe:
            exec:
              command: ["pgrep", "agent"]
            initialDelaySeconds: 10
            periodSeconds: 30
          resources:
            requests:
              memory: "64Mi"
              cpu: "100m"
            limits:
              memory: "128Mi"
              cpu: "250m"
      terminationGracePeriodSeconds: 30
```

Apply it:

```bash
kubectl apply -f generator-agent.yaml
```

Verify the deployment:

```bash
kubectl get pods -l app=generator-agent
kubectl logs -l app=generator-agent
```

### AWS ECS

Create a task definition (`task-definition.json`):

```json
{
  "family": "generator-agent",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "runtimePlatform": {
    "cpuArchitecture": "X86_64",
    "operatingSystemFamily": "LINUX"
  },
  "cpu": "256",
  "memory": "512",
  "containerDefinitions": [
    {
      "name": "agent",
      "image": "ghcr.io/generator-labs/agent:latest",
      "essential": true,
      "secrets": [
        {
          "name": "GENERATOR_AGENT_SID",
          "valueFrom": "arn:aws:secretsmanager:us-east-1:YOUR_ACCOUNT_ID:secret:generator-agent:GENERATOR_AGENT_SID::"
        },
        {
          "name": "GENERATOR_AGENT_TOKEN",
          "valueFrom": "arn:aws:secretsmanager:us-east-1:YOUR_ACCOUNT_ID:secret:generator-agent:GENERATOR_AGENT_TOKEN::"
        }
      ],
      "healthCheck": {
        "command": ["CMD-SHELL", "pgrep agent || exit 1"],
        "interval": 30,
        "timeout": 5,
        "retries": 3,
        "startPeriod": 10
      },
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/generator-agent",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "agent"
        }
      }
    }
  ]
}
```

First, store your credentials in AWS Secrets Manager:

```bash
aws secretsmanager create-secret \
  --name generator-agent \
  --secret-string '{"GENERATOR_AGENT_SID":"your-agent-sid-here","GENERATOR_AGENT_TOKEN":"your-agent-token-here"}'
```

Register the task definition and create the service:

```bash
aws ecs register-task-definition --cli-input-json file://task-definition.json

aws ecs create-service \
  --cluster your-cluster-name \
  --service-name generator-agent \
  --task-definition generator-agent \
  --desired-count 1 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[subnet-xxxx],securityGroups=[sg-xxxx],assignPublicIp=ENABLED}"
```

Verify the service:

```bash
aws ecs describe-services --cluster your-cluster-name --services generator-agent
```

## Networking

The agent requires:

- **Outbound HTTPS** to the Generator Labs platform for task polling and result reporting
- **Outbound access** to any services you configure for monitoring (ports vary by protocol)

If your network requires a proxy for outbound HTTPS, set the `GENERATOR_AGENT_PROXY` environment variable.

## Operations

### Stopping the Agent

The agent handles `SIGTERM` gracefully and will finish any in-progress checks before exiting.

```bash
# Docker Compose
docker compose down

# Kubernetes
kubectl delete deployment generator-agent

# AWS ECS
aws ecs update-service --cluster your-cluster-name --service generator-agent --desired-count 0
```

### Updating

```bash
# Docker Compose
docker compose pull && docker compose up -d

# Kubernetes
kubectl rollout restart deployment/generator-agent

# AWS ECS
aws ecs update-service --cluster your-cluster-name --service generator-agent --force-new-deployment
```

## Troubleshooting

| Symptom | Likely Cause | Resolution |
|---------|-------------|------------|
| Agent exits immediately with a credential error | `GENERATOR_AGENT_SID` or `GENERATOR_AGENT_TOKEN` is missing or malformed | Verify both values are set and match the lengths shown in the management portal (SID: 34 characters, token: 64 characters) |
| Agent starts but reports no tasks | Agent is not assigned any monitors on the platform | Log in to the Generator Labs management portal and assign monitors to this agent |
| Connection timeouts to monitored services | Network or firewall blocking outbound access | Ensure the agent container can reach the target host and port from within its network |
| Agent cannot reach the platform | Outbound HTTPS to `agent.generatorlabs.com` is blocked | Check firewall rules and, if needed, set `GENERATOR_AGENT_PROXY` to route through your corporate proxy |
| DNS resolution failures for monitored hosts | Container DNS is not configured for internal zones | Ensure the container's DNS resolver can resolve internal hostnames (e.g., pass `--dns` to Docker or configure `dnsPolicy` in Kubernetes) |

## Security

To report a vulnerability, see [SECURITY.md](.github/SECURITY.md).

## License

MIT - see [LICENSE](LICENSE) for details.
