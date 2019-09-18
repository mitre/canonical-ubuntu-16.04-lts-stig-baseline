# frozen_string_literal: true

control 'V-75843' do
  title 'The SSH public host key files must have mode 0644 or less permissive.'
  desc  "If a public host key file is modified by an unauthorized user, the SSH
service may be compromised."
  impact 0.5
  tag "gtitle": 'SRG-OS-000480-GPOS-00227'
  tag "gid": 'V-75843'
  tag "rid": 'SV-90523r2_rule'
  tag "stig_id": 'UBTU-16-030310'
  tag "fix_id": 'F-82473r2_fix'
  tag "cci": ['CCI-000366']
  tag "nist": ['CM-6 b', 'Rev_4']
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
  desc 'check', "Verify the SSH public host key files have mode \"0644\" or less
permissive.

Note: SSH public key files may be found in other directories on the system
depending on the installation.

The following command will find all SSH public key files on the system:

# ls -l /etc/ssh/*.pub

-rw-r--r--  1 root  wheel  618 Nov 28 06:43 ssh_host_dsa_key.pub
-rw-r--r--  1 root  wheel  347 Nov 28 06:43 ssh_host_key.pub
-rw-r--r--  1 root  wheel  238 Nov 28 06:43 ssh_host_rsa_key.pub

If any key.pub file has a mode more permissive than \"0644\", this is a
finding."
  desc 'fix', "Note: SSH public key files may be found in other directories on
the system depending on the installation.

Change the mode of public host key files under \"/etc/ssh\" to \"0644\" with
the following command:

# sudo chmod 0644 /etc/ssh/*key.pub

The SSH daemon must be restarted for the changes to take effect. To restart the
SSH daemon, run the following command:

# sudo systemctl restart sshd.service"

  pub_files = command("find /etc/ssh -xdev -name '*.pub' -perm /133").stdout.split("\n")
  if !pub_files.nil? && !pub_files.empty?
    pub_files.each do |pubfile|
      describe file(pubfile) do
        it { should_not be_executable.by('user') }
        it { should_not be_executable.by('group') }
        it { should_not be_writable.by('group') }
        it { should_not be_executable.by('others') }
        it { should_not be_writable.by('others') }
      end
    end
  else
    describe 'No files have a more permissive mode.' do
      subject { pub_files.nil? || pub_files.empty? }
      it { should eq true }
    end
  end
end
