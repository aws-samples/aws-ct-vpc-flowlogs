
# VPC Flow Log automation using AWS Control Tower LifeCycle

Repository for blog [VPC Flow Log automation using AWS Control Tower LifeCycle](https://aws.amazon.com/blogs/mt/vpc-flow-log-with-aws-control-tower-lifecycle/)

There are two deployment methods:
- via console, as per the blog. For this method, use the templates in the `blog` folder
- via Customizations for Control Tower. Use the `cfct` folder. More details on this method below.

## Deploying via Customizations for Control Tower

Included in this Repository is a version of the code from the blog which can be deployed via the [Customizations for Control Tower (CfCT)](https://docs.aws.amazon.com/solutions/latest/customizations-for-aws-control-tower/overview.html) solution.

This version differs in that immediately on deployment, flow logs in all accounts managed by Control Tower are modified to the setting defined in the [manifest.yaml](./manifest.yaml) file - the default in this repo is 'REJECT', but if you wish to have no effect on deployment (and use the tags as per the blog post), set this to DISABLE in the manifest file.

### Zip and upload lambda

As per other CfCT customizations, lambda's used as custom resources should be uploaded to a location prior to executing the CfCT pipeline. 

To create the lambda zip, execute `./zip_lambda.sh`

Then upload to a bucket that is accessible to the AWS Organization, and enter the bucket name into the SSM parameter in mgmt account with key: `/org/primary/storagebucket`. The default values in the manifest file refer to this location (which can be changed if desired)

### CfCT configuration

1. Append the 4 resources of the Resources section of the [manifest file](./manifest.yaml) to your own CfCT manifest file. 
1. Check and configure the parameters within each resource section to reflect your environment.
1. Deploy your CfCT solution as per your setup (using zip or codecommit etc)

### Deploying via console
Follow steps on [VPC Flow Log automation using AWS Control Tower LifeCycle](https://aws.amazon.com/blogs/mt/vpc-flow-log-with-aws-control-tower-lifecycle/) to deploy the solution

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.