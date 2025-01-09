FROM python:3.11

# Set the working directory
WORKDIR /app

# Copy dependencies and install them
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade -r requirements.txt

# Copy application files
COPY . .

# Expose the port used by the app
EXPOSE 80

# Start the Uvicorn server
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8025"]
