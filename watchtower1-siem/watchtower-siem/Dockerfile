FROM python:3.12-slim
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
COPY static static
VOLUME /srv/data
EXPOSE 8000 5514/udp
CMD ["uvicorn","app:app","--host","0.0.0.0","--port","8000"]
