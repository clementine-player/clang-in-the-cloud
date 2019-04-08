# clang-in-the-cloud
HTTP server that reformats C++ source code using clang-format

## Deployment

1. Create all the secrets (available or re-creatable here: https://github.com/settings/apps/clang-formatter):
    ```
    kubectl create secret generic github-clang-app \
      --from-file ~/clang-formatter.2019-04-08.private-key.pem \
      --from-literal 'github-client-id=<client id>' \
      --from-literal 'github-client-secret=<client secret>' \
      --from-literal 'webhook-secret=<webhook secret>'
    ```
1. `kubectl apply -f clang-in-the-cloud.yaml`
