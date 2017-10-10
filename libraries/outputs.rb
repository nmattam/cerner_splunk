# coding: UTF-8

# Cookbook Name:: cerner_splunk
# File Name:: outputs.rb

require_relative 'databag'

module CernerSplunk
  # Module contains functions to configure outputs.conf in a Splunk system
  module Outputs
    def self.configure_outputs(node) # rubocop:disable Metrics/PerceivedComplexity, Metrics/CyclomaticComplexity
      output_stanzas = {}

      if %i[search_head forwarder cluster_master shc_deployer].include? node['splunk']['node_type']
        output_stanzas['tcpout'] = {
          'forwardedindex.0.whitelist' => '.*',
          'forwardedindex.1.blacklist' => '_thefishbucket',
          'forwardedindex.2.whitelist' => ''
        }

        # If we're part of a cluster, we only want to send events to our cluster.
        if node['splunk']['node_type'] == :forwarder
          CernerSplunk.all_clusters(node)
        else
          [CernerSplunk.my_cluster(node)]
        end.each do |(cluster, bag)|
          unless bag['multisite'].nil? && bag['site'].nil?
            encrypt_password = CernerSplunk::ConfTemplate::Transform.splunk_encrypt node: node
            output_stanzas["indexer_discovery:#{bag['site']}"] = {}
            output_stanzas["indexer_discovery:#{bag['site']}"]['pass4SymmKey'] = CernerSplunk::ConfTemplate.compose encrypt_password, CernerSplunk::ConfTemplate::Value.constant(value: 'changeme')
            output_stanzas["indexer_discovery:#{bag['site']}"]['master_uri'] = bag['master_uri']
            output_stanzas["tcpout:#{bag['site']}"] = {}
            output_stanzas["tcpout:#{bag['site']}"]["indexerDiscovery"] = bag['site']
            output_stanzas["tcpout:#{bag['site']}"]["useACK"] = 'true'
            output_stanzas["tcpout"]["defaultGroup"] = bag['site']
            next
          end
          port = bag['receiver_settings']
          port = port['splunktcp'] if port
          port = port['port'] if port
          receivers = bag['receivers']

          if !receivers || receivers.empty? || !port
            Chef::Log.warn "Receiver settings missing or incomplete in configured cluster data bag: #{cluster}"
          else
            output_stanzas["tcpout:#{cluster}"] = {}
            output_stanzas["tcpout:#{cluster}"]['server'] = receivers.collect do |x|
              x.include?(':') ? x : "#{x}:#{port}"
            end.join(',')
          end
        end
      end
      output_stanzas
    end
  end
end
