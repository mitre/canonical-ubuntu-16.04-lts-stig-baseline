control "V-75445" do
  title "The Ubuntu operating system must prevent direct login into the root
account."
  desc  "To assure individual accountability and prevent unauthorized access,
organizational users must be individually identified and authenticated.

    A group authenticator is a generic account used by multiple individuals.
Use of a group authenticator alone does not uniquely identify individual users.
Examples of the group authenticator is the UNIX OS \"root\" user account, the
Windows \"Administrator\" account, the \"sa\" account, or a \"helpdesk\"
account.

    For example, the UNIX and Windows operating systems offer a 'switch user'
capability allowing users to authenticate with their individual credentials
and, when needed, 'switch' to the administrator role. This method provides for
unique individual authentication prior to using a group authenticator.

    Users (and any processes acting on behalf of users) need to be uniquely
identified and authenticated for all accesses other than those accesses
explicitly identified and documented by the organization, which outlines
specific user actions that can be performed on the Ubuntu operating system
without identification or authentication.

    Requiring individuals to be authenticated with an individual authenticator
prior to using a group authenticator allows for traceability of actions, as
well as adding an additional level of protection of the actions that can be
taken with group account knowledge.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000109-GPOS-00056"
  tag "gid": "V-75445"
  tag "rid": "SV-90125r3_rule"
  tag "stig_id": "UBTU-16-010080"
  tag "fix_id": "F-82073r3_fix"
  tag "cci": ["CCI-000770"]
  tag "nist": ["IA-2 (5)", "Rev_4"]
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
  desc "check", "Verify the Ubuntu operating system prevents direct logins to
the root account.

Check that the Ubuntu operating system prevents direct logins to the root
account with the following command:

#  grep root /etc/shadow

root L 11/11/2017 0 99999 7 -1

If any output is returned and the second field is not an \"L\", this is a
finding."
  desc "fix", "Configure the Ubuntu operating system to prevent direct logins to
the root account.

Run the following command to lock the root account:

# passwd -l root"

  describe.one do
    describe shadow.where(user: 'root') do
      its('passwords') { should include '!' }
    end
    describe shadow.where(user: 'root') do
      its('passwords') { should include '*' }
    end
  end
end

