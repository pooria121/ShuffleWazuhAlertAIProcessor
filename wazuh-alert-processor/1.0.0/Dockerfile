FROM frikky/shuffle:app_sdk

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

CMD ["python", "src/app.py"]