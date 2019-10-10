FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH metadefender.MetaDefender

# Switch to assemblyline user
USER assemblyline

# Copy MetaDefender service code
WORKDIR /opt/al_service
COPY . .