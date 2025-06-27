# Topics

- Build a Kubernetes cluster with kind, hardened it with tools and best practices (K8s test)

- Program some Kubernetes Operators in Go

- Give examples of CRD that we can use and how to create them

- Build API application with FastAPI with all tools (black, flake8, mypy, trivy/grype, ...)

- GitLab CI-CD with build Docker image and deploy on Kubernetes: SCA, SAST, DAST

- Compare the former CI-CD pipeline in different environments: GitLab, On-premise, AWS, Azure, GCP, OVH with manual jobs that push in different clouds

- Hardening your Linux OS / VM

- Enforce security inside Kubernetes cluster (Audit logs, Falco, Network Policies, Kube-bench, PSS)

- Configure Firewall + VPS + AZ at the Cloud AWS level (Firewall with Let’s Encrypt, whitelist rules, etc.)

- Add tools for monitoring/protecting your network (in AWS Cloud)

- Use offensive tools to try breaching Pipeline/Cluster/Application

- Hardening your Windows OS

- Authentication and token methods (JWT, Bearer, ...)

- Feynman Path Integral in Python

- Meta Heuristic Algorithms

- Computational Physics

- Quantum Computing

- Algorithms & Linear Data Structures

- Blockchain: Web3.py, Vyper



## Global Schema for CI-CD pipeline

- Build a complete CI-CD pipeline for Python project with: (be careful of DinD problems, use Kaniko)

- Linting step: flake8, isort, mypy

- Quality: Sonar

- Security SCA: check dependencies with Snyk, OWASP Dependency Checker

- Security SAST: Snyk, trufflehog, Bandit

- Security DAST: OWASP ZAP, Burp Suite Dastardly

- Build Docker image

- Security SCA for Docker image: Trivy, Grype

- Artifact management (JFrog Artifactory)

- Push Docker image to Harbor

- Deploy code with ArgoCD (on a Kubernetes cluster) and on standard VM (run Docker image)

- By running a Helm Chart

- Python application to create (Blockchain, Algorithms, Scientific computing, …)

- Be able to push different codebases that work with the same pipeline

- Draw schema with different VMs:

- VM = Sonar, Snyk, etc.

- VM = Harbor (store images)

- VM = ArgoCD (as a pod inside cluster?)

- VM = Vault (manage secrets outside cluster)

- Kubernetes cluster: use EKS on AWS

- Interpose a Keycloak to authenticate in GitLab and the Kubernetes cluster

- Add a monitoring layer with Fluentd on K8s cluster + Elastic/Kibana outside cluster
