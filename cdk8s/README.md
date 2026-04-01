# CascadeGuard CDK8s

## Generating wrappers for custom CRDs

`kubectl get crd warehouses.kargo.akuity.io  -o yaml > imports/kargo/src/warehouses.yaml`

`cdk8s import --language python  --output imports/kargo imports/kargo/src/warehouses.yaml`