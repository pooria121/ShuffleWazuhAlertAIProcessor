FROM frikky/shuffle:app_sdk

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

EXPOSE 33337

CMD ["python", "src/app.py"]