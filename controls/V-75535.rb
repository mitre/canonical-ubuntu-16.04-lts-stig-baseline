control "V-75535" do
  title "Pam_Apparmor must be configured to allow system administrators to pass
information to any other Ubuntu operating system administrator or user, change
security attributes, and to confine all non-privileged users from executing
functions to include disabling, circumventing, or altering implemented security
safeguards/countermeasures."
  desc  "Discretionary Access Control (DAC) is based on the notion that
individual users are \"owners\" of objects and therefore have discretion over
who should be authorized to access the object and in which mode (e.g., read or
write). Ownership is usually acquired as a consequence of creating the object
or via specified ownership assignment. DAC allows the owner to determine who
will have access to objects they control. An example of DAC includes
user-controlled file permissions.

    When discretionary access control policies are implemented, subjects are
not constrained with regard to what actions they can take with information for
which they have already been granted access. Thus, subjects that have been
granted access to information are not prevented from passing (i.e., the
subjects have the discretion to pass) the information to other subjects or
objects. A subject that is constrained in its operation by Mandatory Access
Control policies is still able to operate under the less rigorous constraints
of this requirement. Thus, while Mandatory Access Control imposes constraints
preventing a subject from passing information to another subject operating at a
different sensitivity level, this requirement permits the subject to pass the
information to any subject at the same sensitivity level. The policy is bounded
by the information system boundary. Once the information is passed outside the
control of the information system, additional means may be required to ensure
the constraints remain in effect. While the older, more traditional definitions
of discretionary access control require identity-based access control, that
limitation is not required for this use of discretionary access control.


  "
  impact 0.5
  tag "gtitle": "SRG-OS-000312-GPOS-00122"
  tag "satisfies": ["SRG-OS-000312-GPOS-00122", "SRG-OS-000312-GPOS-00123",
"SRG-OS-000312-GPOS-00124", "SRG-OS-000324-GPOS-00125"]
  tag "gid": "V-75535"
  tag "rid": "SV-90215r2_rule"
  tag "stig_id": "UBTU-16-010600"
  tag "fix_id": "F-82163r1_fix"
  tag "cci": ["CCI-002165", "CCI-002235"]
  tag "nist": ["AC-3 (4)", "AC-6 (10)", "Rev_4"]
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
  desc "check", "Verify the Ubuntu operating system is configured to allow
system administrators to pass information to any other Ubuntu operating system
administrator or user.

Check that \"Pam_Apparmor\" is installed on the system with the following
command:

# sudo apt list libpam-apparmor

libpam-apparmor/xenial-updates,now 2.10.95-0ubuntu2.7 amd64 [installed]

If the \"Pam_Apparmor\" package is not installed, this is a finding.

Check that Pam_Apparmor has properly configured profiles

# sudo apparmor_status

apparmor module is loaded.
13 profiles are loaded.
13 profiles are in enforce mode.
   /sbin/dhclient
   ...
   lxc-container-default-with-nesting
0 profiles are in complain mode.

If all loaded profiles are not in \"enforce\" mode, or there are any profiles
in \"complain\" mode, this is a finding."
  desc "fix", "Configure the Ubuntu operating system to allow system
administrators to pass information to any other Ubuntu operating system
administrator or user.

Install \"Pam_Apparmor\" (if it is not installed) with the following command:

# sudo apt-get install libpam-apparmor

Enable/Activate \"Apparmor\" (if it is not already active) with the following
command:

# sudo systemctl enable apparmor.service

Start \"Apparmor\" with the following command:

# sudo systemctl start apparmor.service

Note: Pam_Apparmor must have properly configured profiles. All configurations
will be based on the actual system setup and organization. See the
\"Pam_Apparmor\" documentation for more information on configuring profiles."

  describe package('libpam-apparmor') do
    it { should be_installed }
  end

  num_loaded_profiles = inspec.command('sudo apparmor_status | grep "profiles are loaded." | cut -f 1 -d " "').stdout
  num_enforced_profiles = inspec.command('sudo apparmor_status | grep "profiles are in enforce mode." | cut -f 1 -d " "').stdout

  describe 'AppArmor Profiles' do
    it 'loaded and enforced' do
      expect(num_loaded_profiles).to eq(num_enforced_profiles)
    end
  end
end

