# clang-in-the-cloud
HTTP server that reformats C++ source code using clang-format

## Deployment

1. `docker build -t gcr.io/clementine-data/clang-in-the-cloud .`
1. `docker push gcr.io/clementine-data/clang-in-the-cloud:latest`
1. `gcloud run deploy clang-in-the-cloud --region=us-central1 --image=gcr.io/clementine-data/clang-in-the-cloud:latest`
