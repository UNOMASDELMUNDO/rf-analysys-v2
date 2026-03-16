FROM grafana/grafana:latest

# Create directories
RUN mkdir -p /var/lib/grafana/dashboards /etc/grafana/provisioning/datasources

# Copy provisioning
COPY dashboards.yml /etc/grafana/provisioning/dashboards/
COPY datasources/prometheus.yml /etc/grafana/provisioning/datasources/

# Copy dashboard JSON
COPY overview.json /var/lib/grafana/dashboards/

ENV GF_SECURITY_ADMIN_PASSWORD=admin
ENV GF_USERS_ALLOW_SIGN_UP=false

EXPOSE 3000
