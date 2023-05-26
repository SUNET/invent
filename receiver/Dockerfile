FROM python:3.11.3-bullseye
ENV INVENT_HOST_DIR=/app/hosts
ENV INVENT_IMAGE_DIR=/app/images
ENV INVENT_DB_DIR=/app/db
RUN  useradd --system --create-home --home-dir /app --shell /bin/bash invent
USER invent
WORKDIR /app
COPY ./main.py .
COPY ./requirements.txt .
RUN pip install --no-cache-dir --requirement requirements.txt 
EXPOSE 8000/tcp
CMD [ ".local/bin/uvicorn", "main:app" ]
