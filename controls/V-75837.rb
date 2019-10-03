# frozen_string_literal: true

control 'V-75837' do
  title "The Ubuntu operating system for all network connections associated
with SSH traffic must immediately terminate at the end of the session or after
10 minutes of inactivity."
  desc  "Automatic session termination addresses the termination of
user-initiated logical sessions in contrast to the termination of network
connections that are associated with communications sessions (i.e., network
disconnect). A logical session (for local, network, and remote access) is
initiated whenever a user (or process acting on behalf of a user) accesses an
organizational information system. Such user sessions can be terminated (and
thus terminate user access) without terminating network sessions.

    Session termination terminates all processes associated with a user's
logical session except those processes that are specifically created by the
user (i.e., session owner) to continue after the session is terminated.

    Conditions or trigger events requiring automatic session termination can
include, for example, organization-defined periods of user inactivity, targeted
responses to certain types of incidents, and time-of-day restrictions on
information system use.

    This capability is typically reserved for specific Ubuntu operating system
functionality where the system owner, data owner, or organization requires
additional assurance.
  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000163-GPOS-00072'
  tag "gid": 'V-75837'
  tag "rid": 'SV-90517r2_rule'
  tag "stig_id": 'UBTU-16-030270'
  tag "fix_id": 'F-82467r2_fix'
  tag "cci": %w[CCI-000879 CCI-001133 CCI-002361]
  tag "nist": ['MA-4 e', 'SC-10', 'AC-12', 'Rev_4']
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
  desc 'check', "Verify that all network connections associated with SSH traffic
are automatically terminated at the end of the session or after \"10\" minutes
of inactivity.

Check that the \"ClientAliveInterval\" variable is set to a value of \"600\" or
less by performing the following command:

# sudo grep -i clientalive /etc/ssh/sshd_config

ClientAliveInterval 600

ClientAliveCountMax  1

If \"ClientAliveInterval\" or \"ClientAliveCountMax\" does not exist,
\"ClientAliveInterval\" is not set to a value of \"600\" or less and
\"ClientAliveCountMax\" is not set to a value of \"1\" or greater in
\"/etc/ssh/sshd_config\", or either line is commented out, this is a finding."
  desc 'fix', "Configure the Ubuntu operating system to automatically terminate
all network connections associated with SSH traffic at the end of a session or
after a \"10\" minute period of inactivity.

Modify or append the following lines in the \"/etc/ssh/sshd_config\" file
replacing \"[Interval]\" with a value of \"600\" or less and \"[CountMax] with
a value of \"1\" or greater:

ClientAliveInterval 600

ClientAliveCountMax  1

In order for the changes to take effect, the SSH daemon must be restarted.

# sudo systemctl restart sshd.service"

  client_alive_interval = input('client_alive_interval')
  client_alive_count_max = input('client_alive_count_max')

  describe sshd_config do
    its('ClientAliveInterval') { should be <= client_alive_interval }
    its('ClientAliveCountMax') { should be >= client_alive_count_max }
  end
end
