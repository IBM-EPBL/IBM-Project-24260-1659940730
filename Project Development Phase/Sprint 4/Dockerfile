# syntax=docker/dockerfile:1

FROM python:3.10

WORKDIR /personal-expense-tracker

COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt

COPY . .

# CMD [ "python3", "-m" , "flask", "run", "--host=0.0.0.0"]

EXPOSE 5000

ENTRYPOINT ["python3"]

CMD ["MyApp.py"]