# Use an official Python runtime as a parent image
FROM python:3.10-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements.txt file into the container
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the frontend folder contents into the container
COPY frontend /app/frontend

# Expose Flask's port
EXPOSE 5000

# Define environment variable to disable buffering
ENV PYTHONUNBUFFERED=1

# Command to run the Flask app
CMD ["python", "frontend/api.py"]
