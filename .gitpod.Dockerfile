# Use a Gitpod recommended base image.
FROM gitpod/workspace-full:latest

# Install Snyk CLI globally.
RUN npm install -g snyk

# Add any other dependencies your extension needs.
# Example: RUN apt-get update && apt-get install -y some-package

# Optional: Set the working directory (if needed).
# WORKDIR /workspace

# Optional: Expose ports if your extension requires them.
# EXPOSE 3000
