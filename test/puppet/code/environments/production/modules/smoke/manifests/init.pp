class smoke {
  notify { 'smoke_test':
    message => "Smoke test passed on ${trusted['certname']}",
  }

  file { '/tmp/puppet_managed':
    ensure  => file,
    content => "Managed by Puppet\nCertname: ${trusted['certname']}\n",
  }

  # Exported resource — each node exports its identity; all nodes collect.
  # Requires PuppetDB (storeconfigs) to resolve <<| |>> queries.
  @@file { "/tmp/exported_from_${trusted['certname']}":
    ensure  => file,
    content => "Exported by ${trusted['certname']}\n",
    tag     => 'node_export',
  }

  File <<| tag == 'node_export' |>>
}
