# mcp-auth-test
App Service configuration (required)

In Web App → Configuration → Application settings set:

WEBSITES_PORT = 8000 (match Docker EXPOSE/PORT)

KC_BASE_URL, KC_REALM, KC_CLIENT_ID as needed

Then your MCP endpoint will be:

https://<your-app>.azurewebsites.net/mcp


$ACR_NAME = "gmlecontainerregistry"
$IMAGE_NAME = "mcp-gx-data"
$TAG = "latest"

# Authenticate
az login

# Build and push
az acr build --image $ACR_NAME.azurecr.io/${IMAGE_NAME}:$TAG `
  --registry $ACR_NAME .
```