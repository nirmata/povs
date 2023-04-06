# Pod Security Standards


These are a collection of policies which implement the Baseline and Restricted profiles of the Kubernetes [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/).

The `Baseline/Default` profile is minimally restrictive and denies the most common vulnerabilities while the `Restricted` profile is more heavily restrictive but follows many more of the common security best practices for Pods.


**NOTE**: the `proc-mount` pod may execute as non-default values for `securityContext.procMount` require the `ProcMountType` feature flag to be enabled.

## Installing the Pod Security Standard policies
Use kustomize to install the baseline or restricted profiles.

**NOTE**: The policies are updated so that they apply ONLY to kyverno-test namespace. 

Install both baseline and restricted policies
```sh
kubectl apply -k .
```

Install restricted profile in enforce mode
```sh
kubectl apply -k enforce/
```
Verify the policies 
```sh
kubectl get cpol
```
Verify the policy reports
```sh
kubectl get polr -n kyverno-test
```
