control "V-75821" do
  title "The Ubuntu operating system must implement address space layout
randomization to protect its memory from unauthorized code execution."
  desc  "Some adversaries launch attacks with the intent of executing code in
non-executable regions of memory or in memory locations that are prohibited.
Security safeguards employed to protect memory include, for example, data
execution prevention and address space layout randomization. Data execution
prevention safeguards can either be hardware-enforced or software-enforced with
hardware providing the greater strength of mechanism.

    Examples of attacks are buffer overflow attacks.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000433-GPOS-00193"
  tag "gid": "V-75821"
  tag "rid": "SV-90501r2_rule"
  tag "stig_id": "UBTU-16-030140"
  tag "fix_id": "F-82451r2_fix"
  tag "cci": ["CCI-002824"]
  tag "nist": ["SI-16", "Rev_4"]
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
  tag "check": "Verify the Ubuntu operating system implements address space
layout randomization (ASLR).

Check that ASLR is configured on the system with the following command:

# sudo sysctl kernel.randomize_va_space

kernel.randomize_va_space = 2

If nothing is returned; we must verify the kernel parameter
\"randomize_va_space\" is set to \"2\" with the following command:

# kernel.randomize_va_space\" /etc/sysctl.conf /etc/sysctl.d/*

kernel.randomize_va_space = 2

If \"kernel.randomize_va_space\" is not set to \"2\", this is a finding."
  tag "fix": "Configure the operating system implement virtual address space
randomization.

Set the system to the required kernel parameter by adding the following line to
\"/etc/sysctl.conf\" (or modify the line to have the required value):

kernel.randomize_va_space=2"
end

