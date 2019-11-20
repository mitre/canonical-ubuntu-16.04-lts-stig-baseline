# frozen_string_literal: true

control 'V-75855' do
  title "An application firewall must protect against or limit the effects of
Denial of Service (DoS) attacks by ensuring the Ubuntu operating system is
implementing rate-limiting measures on impacted network interfaces."
  desc  "DoS is a condition when a resource is not available for legitimate
users. When this occurs, the organization either cannot accomplish its mission
or must operate at degraded capacity.

    This requirement addresses the configuration of the Ubuntu operating system
to mitigate the impact of DoS attacks that have occurred or are ongoing on
system availability. For each system, known and potential DoS attacks must be
identified and solutions for each type implemented. A variety of technologies
exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g.,
limiting processes or establishing memory partitions). Employing increased
capacity and bandwidth, combined with service redundancy, may reduce the
susceptibility to some DoS attacks.
  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000420-GPOS-00186'
  tag "gid": 'V-75855'
  tag "rid": 'SV-90535r1_rule'
  tag "stig_id": 'UBTU-16-030410'
  tag "fix_id": 'F-82485r1_fix'
  tag "cci": ['CCI-002385']
  tag "nist": %w[SC-5 Rev_4]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  desc 'check', "Verify an application firewall is configured to rate limit any
connection to the system.

Check that the Uncomplicated Firewall is configured to rate limit any
connection to the system with the following command:

# sudo ufw show raw

Chain ufw-user-input (1 references)
pkts bytes target prot opt in out source destination
0 0 ufw-user-limit all -- eth0 * 0.0.0.0/0 0.0.0.0/0
ctstate NEW recent: UPDATE seconds: 30 hit_count: 6 name: DEFAULT side:
source mask: 255.255.255.255

0 0 ufw-user-limit-accept all -- eth0 * 0.0.0.0/0 0.0.0.0/0


If any service is not rate limited by the Uncomplicated Firewall, this is a
finding."
  desc 'fix', "Configure the application firewall to protect against or limit
the effects of Denial of Service (DoS) attacks by ensuring the Ubuntu operating
system is implementing rate-limiting measures on impacted network interfaces.

Run the following command replacing \"[service]\" with the service that needs
to be rate limited.

# sudo ufw limit [service]

Or rate-limiting can be done on an interface. An example of adding a rate-limit
on the eth0 interface:

# sudo ufw limit in on eth0"

  ufw_status_output = command('ufw status').stdout.strip
  is_ufw_active = !ufw_status_output.lines.first.include?('inactive')

  if is_ufw_active
    describe ufw_status_output do
      it { should match /(LIMIT)/ }
    end
  else
    describe 'UFW status is active' do
      subject { is_ufw_active }
      it { should be true }
    end
  end
end
