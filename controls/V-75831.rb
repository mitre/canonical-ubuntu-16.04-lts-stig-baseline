# frozen_string_literal: true

control 'V-75831' do
  title "The SSH daemon must be configured to only use Message Authentication
Codes (MACs) employing FIPS 140-2 approved cryptographic hash algorithms."
  desc  "Without cryptographic integrity protections, information can be
altered by unauthorized users without detection.

    Remote access (e.g., RDP) is access to DoD nonpublic information systems by
an authorized user (or an information system) communicating through an
external, non-organization-controlled network. Remote access methods include,
for example, dial-up, broadband, and wireless.

    Cryptographic mechanisms used for protecting the integrity of information
include, for example, signed hash functions using asymmetric cryptography
enabling distribution of the public key to verify the hash information while
maintaining the confidentiality of the secret key used to generate the hash.


  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000250-GPOS-00093'
  tag "satisfies": %w[SRG-OS-000250-GPOS-00093 SRG-OS-000393-GPOS-00173
                      SRG-OS-000394-GPOS-00174]
  tag "gid": 'V-75831'
  tag "rid": 'SV-90511r2_rule'
  tag "stig_id": 'UBTU-16-030240'
  tag "fix_id": 'F-82461r2_fix'
  tag "cci": %w[CCI-001453 CCI-002890 CCI-003123]
  tag "nist": ['AC-17 (2)', 'MA-4 (6)', 'MA-4 (6)', 'Rev_4']
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
  desc 'check', "Verify the SSH daemon is configured to only use Message
Authentication Codes (MACs) that employ FIPS 140-2 approved ciphers.

Check that the SSH daemon is configured to only use MACs that employ FIPS 140-2
approved ciphers with the following command:

# sudo grep -i macs /etc/ssh/sshd_config
MACs hmac-sha2-256,hmac-sha2-512

If any ciphers other than \"hmac-sha2-256\" or \"hmac-sha2-512\" are listed, or
the retuned line is commented out, this is a finding."
  desc 'fix', "Configure the Ubuntu operating system to allow the SSH daemon to
only use Message Authentication Codes (MACs) that employ FIPS 140-2 approved
ciphers.

Edit the \"/etc/ssh/sshd_config\" file to uncomment or add the line for the
\"MACs\" keyword and set its value to \"hmac-sha2-256\" and/or
\"hmac-sha2-512\":

MACs hmac-sha2-256,hmac-sha2-512

The SSH daemon must be restarted for the changes to take effect. To restart the
SSH daemon, run the following command:

# sudo systemctl restart sshd.service"

  @macs_array = inspec.sshd_config.params['macs']

  @macs_array = @macs_array.first.split(',') unless @macs_array.nil?

  describe @macs_array do
    it { should be_in %w[hmac-sha2-256 hmac-sha2-512] }
  end
end
