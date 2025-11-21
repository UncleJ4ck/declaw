# Use an official Python runtime as a parent image
FROM python:3.10-slim

# Set the working directory to /app
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Install OpenJDK for running Java applications (Apktool, uber-apk-signer)
# and ADB for interacting with Android devices
RUN apt-get update && \
    apt-get install -y default-jdk android-tools-adb adb usbutils && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create directories for storing packages and patched APKs
RUN mkdir -p /app/packages /app/patched /app/utils

# Make port 5037 available to the world outside this container
# This port is used by ADB server
EXPOSE 5037

# Set the Docker container's entrypoint to the script
ENTRYPOINT ["python3", "adb-ssl-unpinning.py"]