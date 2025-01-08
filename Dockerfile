FROM python:3.11

# Buat direktori kerja
WORKDIR /app

# Salin file requirements terlebih dahulu (untuk caching layer Docker)
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir --upgrade -r requirements.txt

# Salin seluruh isi project (termasuk app.py, model, dsb.) ke /app
COPY . .

# Expose port 80 (opsional, tapi bagus untuk dokumentasi Docker)
EXPOSE 80

# Jalankan uvicorn
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "80"]








# FROM python:3.11

# # Set the working directory in the container
# WORKDIR /code

# # Copy the requirements file into the container
# COPY requirements.txt .

# # Install the dependencies
# RUN pip install --no-cache-dir --upgrade -r requirements.txt

# # Copy the rest of the application code into the container
# COPY . .

# # Expose the port that the app will run on
# EXPOSE 3100

# # Command to run the application using Uvicorn
# CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "3100", "--workers", "4"]