# Pod Security Standards


These are a collection of policies which implement the Baseline and Restricted profiles of the Kubernetes [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/).

The `Baseline/Default` profile is minimally restrictive and denies the most common vulnerabilities while the `Restricted` profile is more heavily restrictive but follows many more of the common security best practices for Pods.


**NOTE**: the `proc-mount` pod may execute as non-default values for `securityContext.procMount` require the `ProcMountType` feature flag to be enabled.

## Installing the Pod Security Standard policies
Use kustomize to install the baseline or restricted profiles.

**NOTE**: The policies are updated so that they apply ONLY to kyverno-test namespace. 

Install both baseline and restricted policies in `Enforce` mode using kustomize. You can install kustomize from [here](https://kubectl.docs.kubernetes.io/installation/kustomize/) if needed. 
```sh
kustomize build https://github.com/kyverno/policies/pod-security/enforce | kubectl apply -f - 
```
Verify the policies 
```sh
kubectl get cpol
```
Now try to run an insecure workload using below command. You will see that the pod will be blocked by Pod Security Policies as the policies are deployed in the `Enforce` mode
```sh
$ kubectl run nginx --image nginx --dry-run=server
Error from server: admission webhook "validate.kyverno.svc-fail" denied the request:

policy Pod/default/nginx for resource violations:

disallow-capabilities-strict:
  require-drop-all: 'validation failure: Containers must drop `ALL` capabilities.'
disallow-privilege-escalation:
  privilege-escalation: 'validation error: Privilege escalation is disallowed. The
    fields spec.containers[*].securityContext.allowPrivilegeEscalation, spec.initContainers[*].securityContext.allowPrivilegeEscalation,
    and spec.ephemeralContainers[*].securityContext.allowPrivilegeEscalation must
    be set to `false`. rule privilege-escalation failed at path /spec/containers/0/securityContext/'
require-run-as-nonroot:
  run-as-non-root: 'validation error: Running as root is not allowed. Either the field
    spec.securityContext.runAsNonRoot must be set to `true`, or the fields spec.containers[*].securityContext.runAsNonRoot,
    spec.initContainers[*].securityContext.runAsNonRoot, and spec.ephemeralContainers[*].securityContext.runAsNonRoot
    must be set to `true`. rule run-as-non-root[0] failed at path /spec/securityContext/runAsNonRoot/
    rule run-as-non-root[1] failed at path /spec/containers/0/securityContext/'
restrict-seccomp-strict:
  check-seccomp-strict: 'validation error: Use of custom Seccomp profiles is disallowed.
    The fields spec.securityContext.seccompProfile.type, spec.containers[*].securityContext.seccompProfile.type,
    spec.initContainers[*].securityContext.seccompProfile.type, and spec.ephemeralContainers[*].securityContext.seccompProfile.type
    must be set to `RuntimeDefault` or `Localhost`. rule check-seccomp-strict[0] failed
    at path /spec/securityContext/seccompProfile/ rule check-seccomp-strict[1] failed
    at path /spec/containers/0/securityContext/'
```sh
Verify the policy reports
```sh
kubectl get polr -n kyverno-test
```
