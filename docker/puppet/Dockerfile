# OpenVox Server (JVM-based) image for the puppet-ca integration test stack.
#
# Installs OpenVox Server 8 + PuppetDB terminus from the official Vox Pupuli
# repository.  The built-in Puppet CA is disabled; the Go puppet-ca service
# handles all certificate operations.
#
# The entrypoint.sh bootstraps TLS certificates from the Go CA, configures
# webserver.conf and puppet.conf, then starts `puppetserver foreground`.

FROM quay.io/centos/centos:stream10

# Install OpenVox Server + PuppetDB terminus + runtime tools.
RUN dnf -y install https://yum.voxpupuli.org/openvox8-release-el-10.noarch.rpm && \
    dnf -y install openvox-server openvoxdb-termini curl openssl util-linux-user && \
    dnf clean all

# Lower the default JVM heap for the integration test environment.
RUN echo 'JAVA_ARGS="-Xms512m -Xmx512m -XX:ReservedCodeCacheSize=512m"' \
        >> /etc/sysconfig/puppetserver

ENV PATH=/opt/puppetlabs/server/bin:/opt/puppetlabs/puppet/bin:${PATH}

# Create SSL directory tree; openvox-server RPM creates the puppet user.
RUN mkdir -p /etc/puppetlabs/puppet/ssl && \
    chown puppet:puppet /etc/puppetlabs/puppet/ssl

# Copy bootstrap + startup entrypoint.
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 8140

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
