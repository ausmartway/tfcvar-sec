# tfcvar-sec

As the most popular Infrastructure as Code tool(or one of), Terraform helps in configuring, provisioning, and managing the infrastructure accross 400+ providers. The first thing Terraform needs is the credential so that it can interact with the provider's API. The credentials used by terraform are generally priviliged so that terraform can create/update/destroy resources. It is very important to keep those credentials secure.

Terraform Cloud is a secure/reliable and governed IaC pipeline that helps teams use Terraform cli all together. It provides a means for practitioner to store their credentials as terraform or enviroment variable, which can be marked as sensitive. Sensitive variables are encrypted and not readable by any practitioner.

tfcvar-sec is a tool that will scan terraform and enviroment variables configured in Terraform Cloud, and let you know if there is any variable that may contain secrets but hasn't been marked as sensitive.


## Different ways of providing credentials to Terraform Providers

The provider credentials can be provided to Terraform by several means. Below are a few different ways of configuring credential for the most popular Terraform provider, aws:

### static secrets
```terraform
provider "aws" {
  region     = "us-west-2"
  access_key = "my_aws_access_key"
  secret_key = "my_aws_secret_key"
}
```
Hardcoding static secrets risks secrets leakage, whoever get access to your config files will be able to use it. You know you shouldn't use it.


### using terraform variable
```terraform
provider "aws" {
  region     = "us-west-2"
  access_key = var.aws_access_key
  secret_key = var.aws_secret_key
}
```
This method is an improvement to hardcoding secrets, as the values of terraform variable don't have to be stored in the code. They can be provided by the CI/CD pipeline at runtime. However this method has it's own risk, as the credentials are provided as terraform variable, it's value will be accessble by terraform code, for example:

```terraform
output "aws_credentials" {
    value = "aws_access_key=${var.aws_access_key}\naws_secret_key=${var.aws_secret_key}"
}
```
Terraform variables can be further secured by marking terraform variable [sensitive](https://learn.hashicorp.com/tutorials/terraform/sensitive-variables), but it relies on the practitioner and administrators to enforce good coding practise. 

### using Enviroment Variables to configure provider credentials

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
Enviroment variables are more secure than terraform variables, as they can not be referenced by any terraform code.

### using IAM roles
Running Terraform cli on the cloud, and 




