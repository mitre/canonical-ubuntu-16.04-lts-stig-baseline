# frozen_string_literal: true

control 'V-75829' do
  title "The Ubuntu operating system must implement DoD-approved encryption to
protect the confidentiality of SSH connections."
  desc  "Without confidentiality protection mechanisms, unauthorized
individuals may gain access to sensitive information via a remote access
session.

    Remote access is access to DoD nonpublic information systems by an
authorized user (or an information system) communicating through an external,
non-organization-controlled network. Remote access methods include, for
example, dial-up, broadband, and wireless.

    Encryption provides a means to secure the remote connection to prevent
unauthorized access to the data traversing the remote access connection (e.g.,
RDP), thereby providing a degree of confidentiality. The encryption strength of
a mechanism is selected based on the security categorization of the information.
  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000033-GPOS-00014'
  tag "gid": 'V-75829'
  tag "rid": 'SV-90509r2_rule'
  tag "stig_id": 'UBTU-16-030230'
  tag "fix_id": 'F-82459r2_fix'
  tag "cci": ['CCI-000068']
  tag "nist": ['AC-17 (2)', 'Rev_4']
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
  desc 'check', "Verify the SSH daemon is configured to only implement
DoD-approved encryption.

Check the SSH daemon's current configured ciphers by running the following
command:

# sudo grep -i ciphers /etc/ssh/sshd_config | grep -v '^#'

Ciphers aes128-ctr aes192-ctr, aes256-ctr

If any ciphers other than \"aes128-ctr\", \"aes192-ctr\", or \"aes256-ctr\" are
listed, the \"Ciphers\" keyword is missing, or the retuned line is commented
out, this is a finding."
  desc 'fix', "Configure the Ubuntu operating system to allow the SSH daemon to
only implement DoD-approved encryption.

Edit the SSH daemon configuration \"/etc/ssh/sshd_config\" and remove any
ciphers not starting with \"aes\" and remove any ciphers ending with \"cbc\".
If necessary, append the \"Ciphers\" line to the \"/etc/ssh/sshd_config\"
document.

Ciphers aes128-ctr,aes192-ctr,aes256-ctr

The SSH daemon must be restarted for the changes to take effect. To restart the
SSH daemon, run the following command:

# sudo systemctl restart sshd.service"

  @ciphers_array = inspec.sshd_config.params['ciphers']

  @ciphers_array = @ciphers_array.first.split(',') unless @ciphers_array.nil?

  describe @ciphers_array do
    it { should be_in %w[aes128-ctr aes192-ctr aes256-ctr] }
  end
end
