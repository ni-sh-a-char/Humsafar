# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Install necessary system packages
RUN apt-get update && apt-get install -y \
    tshark \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set up a working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose the Streamlit port
EXPOSE 80

# Define the command to run your application
ENTRYPOINT ["streamlit", "run"]
CMD ["Humsafar.py", "--server.enableCORS=false", "--server.enableWebsocketCompression=false", "--server.enableXsrfProtection=false"]
