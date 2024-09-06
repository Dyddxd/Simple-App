# FastAPI Application

This is a FastAPI web application with user registration, login, and profile management features. It includes rate limiting using `slowapi`, password hashing with `passlib`, and Prometheus monitoring integration.

## Features

- User registration and login
- Profile setup with user description, age, and occupation
- Session management
- Rate limiting (5 requests per minute per IP)
- Prometheus monitoring integration

## Requirements

- FastAPI
- Uvicorn
- Python-dotenv
- Passlib
- Itsdangerous
- MySQL Connector
- Starlette
- Slowapi
- Prometheus FastAPI Instrumentator
- Jinja2
- Python-multipart

## Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/your-username/your-repo.git
   cd your-repo
2. **Create and activate a virtual environment:**
    
    ```bash
    python -m venv .venv
    source .venv/bin/activate  # On Windows use .venv\Scripts\activate
3. **Install the required packages:**
    ```bash
    pip install -r requirements.txt
4. **Create a *.env* file:**

    ```bash
    SECRET_KEY=your_secret_key
    DB_HOST=your_database_host
    DB_USER=your_database_user
    DB_PASSWORD=your_database_password
    DB_NAME=your_database_name
    
## Running the Application

1. **Start the FastAPI application with Uvicorn:**

    ```bash
    uvicorn main:app --host 0.0.0.0 --port 8000
    
The application will be available at *http://localhost:8000*

2. **Testing Rate Limiting:**

    ```bash
    ab -n 100 -c 10 http://localhost:8000/register

## Prometheus/Grafana Monitoring

1. **Prometheus configuration:**

Configure *prometheus.yml* file as you need but basically it is already designed to work fine with FastAPI application.

2. **Run Prometheus using Docker:**

    ```bash
    docker run -d --name prometheus --network host -p 9090:9090 -v $(pwd)/prometheus.yml:/etc/prometheus/prometheus.yml prom/prometheus

Prometheus will be available at http://localhost:9090

Also you can check your Prometheus targets at http://localhost:9090/targets

3. **Run Grafana using Docker:**

    ```bash
    docker run -d --name grafana -p 3000:3000 grafana/grafana
4. **Add Prometheus as Data Source and test inside the Grafana UI**

    ```bash
    ip a

In this configuration, you must use local IP address of your PC as url for Prometheus http://local_IP_address:9090