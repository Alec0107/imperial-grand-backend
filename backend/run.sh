#!/bin/bash

echo "🟢 Starting Imperial Grand Backend..."

# railway deployed d postgresql
#export POSTGRES_URL=jdbc:postgresql://trolley.proxy.rlwy.net:25525/railway
#export POSTGRES_USERNAME=postgres
#export POSTGRES_PASSWORD=ezkJEnRhJTAngTSmvWwrehEjLocAxEuq

# local db postgresql
export POSTGRES_URL=jdbc:postgresql://localhost:5432/imperial
export POSTGRES_USERNAME=postgres
export POSTGRES_PASSWORD=Nicholas102405

# jwt key
export JWT_KEY=UjMFleq9Ei/6yNWdoE/cOpOyr9YzWvbvVmhKxzHACbY=

./gradlew bootRun

