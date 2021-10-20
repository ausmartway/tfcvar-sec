# tfcvar-sec

## TLDR

tfcvar-sec is a tool that scans and fixes terraform and enviroment variables configured in Terraform Cloud, it finds any variable that may contain secrets but hasn't been marked as sensitive.

## The problem

As the most popular Infrastructure as Code tool(or one of), Terraform helps in configuring, provisioning, and managing the infrastructure accross 400+ providers. The first thing Terraform needs is the credential so that it can interact with the provider's API. The credentials used by terraform are generally priviliged so that terraform can create/update/destroy resources. It is very important to keep those credentials secure.

Terraform Cloud is a secure/reliable and governed IaC pipeline that helps teams use Terraform cli all together. It provides a means for practitioner to store their credentials as terraform or enviroment variable, which can be marked as sensitive. Sensitive variables are encrypted and not readable by any practitioner.

### Different ways of providing credentials to Terraform Providers

The provider credentials can be provided to Terraform by several means. Below are a few different ways of configuring credential for the most popular Terraform provider, aws:

#### static secrets

```terraform
provider "aws" {
  region     = "us-west-2"
  access_key = "my_aws_access_key"
  secret_key = "my_aws_secret_key"
}
```

Hardcoding static secrets risks secrets leakage, whoever get access to your config files will be able to use it. You know you shouldn't use it.

#### using terraform variable

```terraform
provider "aws" {
  region     = "us-west-2"
  access_key = var.aws_access_key
  secret_key = var.aws_secret_key
}
```

This method is an improvement to hardcoding secrets, as the values of terraform variable don't have to be stored in the code. They can be configured in Terraform Cloud. However this method has it's own risk, as the credentials are provided as terraform variable, it's value will be accessble by terraform code, for example:

```terraform
output "aws_credentials" {
    value = "aws_access_key=${var.aws_access_key}\naws_secret_key=${var.aws_secret_key}"
}
```

Terraform variables can be further secured by marking terraform variable [sensitive](https://learn.hashicorp.com/tutorials/terraform/sensitive-variables), but it still relies on the practitioner and administrators to enforce good coding practise, eg, be very careful with [nonsensitive](https://www.terraform.io/docs/language/functions/nonsensitive.html) function.

#### Enviroment Variables

```bash
export AWS_ACCESS_KEY_ID=my_aws_access_key
export AWS_SECRET_ACCESS_KEY=my_aws_secret_key
```

Then:

```terraform
provider "aws" {
  region     = "us-west-2"
}
```

Enviroment variables are more secure than terraform variables, as they can not be referenced by any terraform code. Enviroment variables also have fixed name per provider, which makes it easy to be identified.

#### using IAM roles/Instance Profiles, etc

Running Terraform cli on the cloud, and use predefined IAM roles. There is no credential involved, but this will only work with one major providers - you can't use aws IAM role to provision on gcp, or vice versa.

## The solution

Based on above, providing provider credentials via Enviroment variables perhaps is the most widely used and most secure way(different ways of providing provider credentials can be found at the end of this Readme). It still relies on TFC admins making those that could contain secrets sensitive.

tfcvar-sec is a tool that scans terraform and enviroment variables configured in Terraform Cloud, find any variable that may contain secrets but hasn't been marked as sensitive, then provide option to fix them.

Credentials provided to terraform providers via enviroment variables have fixed key, this makes it easy for tfcvar-sec to identify. Enviroment variables identified by tfcvar-sec will be printed as Red.

Credentials provided to terraform providers via terraform variable is harder to identify, as the variable names can be customised. tfcvar-sec just do a best effort guess based on name of the variable. Identified terraform variables will be printed as Yellow.

Terraform variable values can also be provided as enviroment variable, eg TF_VAR_varname, those will be printed as Yellow as well.

Below is an example output:

![tfcvar-sec](https://raw.githubusercontent.com/ausmartway/tfcvar-sec/main/png/tfcvar-sec.png)

## Installation

Note that you don't have to install tfcvar-sec if you have docker. please see usage section for details.

### Macos

```bash
brew tap ausmartway/tfcvar-sec
brew install tfcvar-sec
```

### Linux

```bash
curl -L https://raw.githubusercontent.com/ausmartway/tfcvar-sec/main/install.sh | sudo bash
```

Please note that sudo is required so that tfcvar-sec can be installed into /usr/local/bin directory

### Windows

Download from [releases](https://github.com/ausmartway/tfcvar-sec/releases), unzip and copy the binary to system %PATH%.

## usage

tfcvar-sec only works with Terraform Cloud for now. You need a Terraform Cloud token which will be used by tfcvar-sec to find all orgnizations,workspaces and variables. eg:

```bash
TFE_TOKEN=YOUROWNTOKEN  tfcvar-sec scan
```

or

```bash
tfcvar-sec scan --token YOUROWNTOKEN
```

tfcvar-sec will read Terraform Cloud credentials file if no tokens are provided via cli or enviroment variable. This is $HOME/.terraform.d/credentials.tfrc.json by default. eg:

```bash
tfcvar-sec scan
```

If you have docker, you can use below command:

```bash
docker run --rm -ti --env \
TFE_TOKEN=YOUROWNTOKEN \
ausmartway/tfcvar-sec scan
```

or

```bash
docker run --rm -ti ausmartway/tfcvar-sec scan \
--token YOUROWNTOKEN
```

You can also provide cli flag --fixcritical and/or --fixwarning to ask tfcvar-sec scan command to fix the issues for you, those two flags are set to false by default.

## Colaboration

Please raise issues or pull request if you want to add to the list, providing the URL to related provider documents.
