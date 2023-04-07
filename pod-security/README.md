# Pod Security Standards


These are a collection of policies which implement the Baseline and Restricted profiles of the Kubernetes [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/).

The `Baseline/Default` profile is minimally restrictive and denies the most common vulnerabilities while the `Restricted` profile is more heavily restrictive but follows many more of the common security best practices for Pods.


**NOTE**: the `proc-mount` pod may execute as non-default values for `securityContext.procMount` require the `ProcMountType` feature flag to be enabled.

## Installing the Pod Security Standard policies
Use kustomize to install the baseline and restricted profiles.

**NOTE**: The policies are updated so that they apply ONLY to `kyverno-test` namespace. 

Install both baseline and restricted policies in `Enforce` mode using kustomize. You can install kustomize from [here](https://kubectl.docs.kubernetes.io/installation/kustomize/) if needed. 
```sh
kustomize build https://github.com/nirmata/povs/pod-security/enforce  | kubectl apply -f - 
```
Verify the policies 
```sh
kubectl get cpol
NAME                             BACKGROUND   VALIDATE ACTION   READY   AGE
disallow-capabilities            true         enforce           true    20m
disallow-capabilities-strict     true         enforce           true    20m
disallow-host-namespaces         true         enforce           true    20m
disallow-host-path               true         enforce           true    19m
disallow-host-ports              true         enforce           true    19m
disallow-host-process            true         enforce           true    19m
disallow-privilege-escalation    true         enforce           true    19m
disallow-privileged-containers   true         enforce           true    19m
disallow-proc-mount              true         enforce           true    19m
disallow-selinux                 true         enforce           true    19m
require-run-as-non-root-user     true         enforce           true    19m
require-run-as-nonroot           true         enforce           true    19m
restrict-apparmor-profiles       true         enforce           true    19m
restrict-seccomp                 true         enforce           true    19m
restrict-seccomp-strict          true         enforce           true    19m
restrict-sysctls                 true         enforce           true    19m
restrict-volume-types            true         enforce             true    19m
```
Now try to run an insecure workload in `kyverno-test` namespace using below command. You will see that the pod will be blocked by Pod Security Policies as the policies are deployed in the `Enforce` mode
```sh
$ kubectl create ns kyverno-test
$ kubectl -n kyverno-test run nginx --image nginx --dry-run=server
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
```
Now patch the kyverno policies using the command below to deploy them in `Audit` mode. Verify the policies are deployed in `Audit` mode
```sh
for j in $(kubectl get cpol --no-headers | awk '{print $1}'); do kubectl patch cpol $j --type='json' -p='[{"op": "replace", "path": "/spec/validationFailureAction", "value":"Audit"}]';done
clusterpolicy.kyverno.io/disallow-capabilities patched
clusterpolicy.kyverno.io/disallow-capabilities-strict patched
clusterpolicy.kyverno.io/disallow-host-namespaces patched
clusterpolicy.kyverno.io/disallow-host-path patched
clusterpolicy.kyverno.io/disallow-host-ports patched
clusterpolicy.kyverno.io/disallow-host-process patched
clusterpolicy.kyverno.io/disallow-privilege-escalation patched
clusterpolicy.kyverno.io/disallow-privileged-containers patched
clusterpolicy.kyverno.io/disallow-proc-mount patched
clusterpolicy.kyverno.io/disallow-selinux patched
clusterpolicy.kyverno.io/require-run-as-non-root-user patched
clusterpolicy.kyverno.io/require-run-as-nonroot patched
clusterpolicy.kyverno.io/restrict-apparmor-profiles patched
clusterpolicy.kyverno.io/restrict-seccomp patched
clusterpolicy.kyverno.io/restrict-seccomp-strict patched
clusterpolicy.kyverno.io/restrict-sysctls patched
clusterpolicy.kyverno.io/restrict-volume-types patched

$ kubectl get cpol
NAME                             BACKGROUND   VALIDATE ACTION   READY   AGE
disallow-capabilities            true         Audit             true    27m
disallow-capabilities-strict     true         Audit             true    27m
disallow-host-namespaces         true         Audit             true    27m
disallow-host-path               true         Audit             true    27m
disallow-host-ports              true         Audit             true    27m
disallow-host-process            true         Audit             true    27m
disallow-privilege-escalation    true         Audit             true    27m
disallow-privileged-containers   true         Audit             true    27m
disallow-proc-mount              true         Audit             true    27m
disallow-selinux                 true         Audit             true    27m
require-run-as-non-root-user     true         Audit             true    27m
require-run-as-nonroot           true         Audit             true    27m
restrict-apparmor-profiles       true         Audit             true    27m
restrict-seccomp                 true         Audit             true    27m
restrict-seccomp-strict          true         Audit             true    27m
restrict-sysctls                 true         Audit             true    27m
restrict-volume-types            true         Audit             true    27m

```
Now try to deploy the insecure workload again. You will see that it will pod will get deployed as the policies are deployed in `Audit` mode. The violations will be reported in the policy reports. 
```sh
kubectl -n kyverno-test run nginx --image nginx --dry-run=server
pod/nginx created (server dry run)

 kubectl get polr -Akyverno-test   cpol-disallow-capabilities            1      0      0      0       0      4m7s
kyverno-test   cpol-disallow-capabilities-strict     1      1      0      0       0      4m7s
kyverno-test   cpol-disallow-host-namespaces         1      0      0      0       0      4m7s
kyverno-test   cpol-disallow-host-path               1      0      0      0       0      4m7s
kyverno-test   cpol-disallow-host-ports              1      0      0      0       0      4m7s
kyverno-test   cpol-disallow-host-process            1      0      0      0       0      4m7s
kyverno-test   cpol-disallow-privilege-escalation    0      1      0      0       0      4m7s
kyverno-test   cpol-disallow-privileged-containers   1      0      0      0       0      4m7s
kyverno-test   cpol-disallow-proc-mount              1      0      0      0       0      4m7s
kyverno-test   cpol-disallow-selinux                 2      0      0      0       0      4m7s
kyverno-test   cpol-require-run-as-non-root-user     1      0      0      0       0      4m7s
kyverno-test   cpol-require-run-as-nonroot           0      1      0      0       0      4m7s
kyverno-test   cpol-restrict-apparmor-profiles       1      0      0      0       0      4m7s
kyverno-test   cpol-restrict-seccomp                 1      0      0      0       0      4m7s
kyverno-test   cpol-restrict-seccomp-strict          0      1      0      0       0      4m7s
kyverno-test   cpol-restrict-sysctls                 1      0      0      0       0      4m7s
kyverno-test   cpol-restrict-volume-types            1      0      0      0       0      4m7s


```
