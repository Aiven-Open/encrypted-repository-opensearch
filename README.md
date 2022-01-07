# Template for creating OpenSearch Plugins
This Repo is a GitHub Template repository ([Learn more about that](https://docs.github.com/articles/creating-a-repository-from-a-template/)).
Using it would create a new repo that is the boilerplate code required for an [OpenSearch Plugin](https://opensearch.org/blog/technical-posts/2021/06/my-first-steps-in-opensearch-plugins/). 
This plugin on its own would not add any functionality to OpenSearch, but it is still ready to be installed.
It comes packaged with:
 - Integration tests of two types: Yaml and IntegTest.
 - Empty unit tests file
 - Notice and License files (Apache License, Version 2.0)
 - A `build.gradle` file supporting this template's current state.

---
---
1. [Create your plugin repo using this template](#create-your-plugin-repo-using-this-template)
2. [Fix up the template to match your new plugin requirements](#fix-up-the-template-to-match-your-new-plugin-requirements)
   - [Plugin Name](#plugin-name)
   - [Plugin Path](#plugin-path)
   - [Update the `build.gradle` file](#update-the-buildgradle-file)
   - [Update the tests](#update-the-tests)
   - [Running the tests](#running-the-tests)
   - [Running testClusters with the plugin installed](#running-testclusters-with-the-plugin-installed)
   - [Cleanup template code](#cleanup-template-code)
   - [Editing the CI workflow](#Editing-the-CI-workflow)
3. [License](#license)
4. [Copyright](#copyright)
---
---

## Create your plugin repo using this template
Click on "Use this Template"

![Use this Template](https://docs.github.com/assets/images/help/repository/use-this-template-button.png)

Name the repository, and provide a description. We recommend using the following naming conventions:
- Do not include the word `plugin` in the repo name (e.g. [job-scheduler](https://github.com/opensearch-project/job-scheduler))
- Use lowercase repo names
- Use spinal case for repo names (e.g. [job-scheduler](https://github.com/opensearch-project/job-scheduler))
- do not include the word `OpenSearch` or `OpenSearch Dashboards` in the repo name
- Provide a meaningful description, e.g. `An OpenSearch Dashboards plugin to perform real-time and historical anomaly detection on OpenSearch data`.


## Fix up the template to match your new plugin requirements

This is the file tree structure of the source code, as you can see there are some things you will want to change.

```
`-- src
    |-- main
    |   `-- java
    |       `-- org
    |           `-- opensearch
    |               `-- path
    |                   `-- to
    |                       `-- plugin
    |                           `-- RenamePlugin.java
    |-- test
    |   `-- java
    |       `-- org
    |           `-- opensearch
    |               `-- path
    |                   `-- to
    |                       `-- plugin
    |                           |-- RenamePluginIT.java
    |                           `-- RenameTests.java
    `-- yamlRestTest
        |-- java
        |   `-- org
        |       `-- opensearch
        |           `-- path
        |               `-- to
        |                   `-- plugin
        |                       `-- RenameClientYamlTestSuiteIT.java
        `-- resources
            `-- rest-api-spec
                `-- test
                    `-- 10_basic.yml

```

### Plugin Name
Now that you have named the repo, you can change the plugin class `RenamePlugin.java` to have a meaningful name, keeping the `Plugin` suffix.
Change `RenamePluginIT.java`, `RenameTests.java`, and `RenameClientYamlTestSuiteIT.java` accordingly, keeping the `PluginIT`, `Tests`, and `ClientYamlTestSuiteIT` suffixes.

### Plugin Path 
Notice these paths in the source tree:
```
-- path
   `-- to
       `-- plugin
```

Let's call this our *plugin path*, as the plugin class would be installed in OpenSearch under that path.
This can be an existing path in OpenSearch, or it can be a unique path for your plugin. We recommend changing it to something meaningful.
Change all these path occurrences to match the path you chose for your plugin:
- Chose a new plugin path
- Go to the `build.gradle` file and update the `pathToPlugin` param with the path you've chosen (use dotted notation)
- Run `./gradlew preparePluginPathDirs` in the terminal
- Move the java classes into the new directories (will require to edit the `package` name in the files as well)
- Delete the old directories

### Update the `build.gradle` file

Update the following section, using the new repository name and description, plugin class name, and plugin path:

```
def pluginName = 'rename'                    // Can be the same as new repo name
def pluginDescription = 'Custom plugin'      // Can be same as new repo description
def pathToPlugin = 'path.to.plugin'          // The path you chose for the plugin
def pluginClassName = 'RenamePlugin'         // The plugin class name
```

Next update the version of OpenSearch you want the plugin to be installed into. Change the following param:
```
    ext {
        opensearch_version = "1.0.0-beta1" // <-- change this to the version your plugin requires
    }
```

### Update the tests
Notice that in the tests we are checking that the plugin was installed by sending a GET `/_cat/plugins` request to the cluster and expecting `rename` to be in the response.
In order for the tests to pass you must change `rename` in `RenamePluginIT.java` and in `10_basic.yml` to be the `pluginName` you defined in the `build.gradle` file in the previous section.

### Running the tests
You may need to install OpenSearch and build a local artifact for the integration tests and build tools ([Learn more here](https://github.com/opensearch-project/opensearch-plugins/blob/main/BUILDING.md)):

```
~/OpenSearch (main)> git checkout 1.0.0-beta1 -b beta1-release
~/OpenSearch (main)> ./gradlew publishToMavenLocal -Dbuild.version_qualifier=beta1 -Dbuild.snapshot=false
```

Now you can run all the tests like so:
```
./gradlew check
```

### Running testClusters with the plugin installed 
```
./gradlew run
```

Then you can see that your plugin has been installed by running: 
```
curl -XGET 'localhost:9200/_cat/plugins'
```

### Cleanup template code
- You can now delete the unused paths - `path/to/plugin`.
- Remove this from the `build.gradle`:

```
tasks.register("preparePluginPathDirs") {
    mustRunAfter clean
    doLast {
        def newPath = pathToPlugin.replace(".", "/")
        mkdir "src/main/java/org/opensearch/$newPath"
        mkdir "src/test/java/org/opensearch/$newPath"
        mkdir "src/yamlRestTest/java/org/opensearch/$newPath"
    }
}
```

- Last but not least, add your own `README.md` instead of this one 

### Editing the CI workflow
You may want to edit the CI of your new repo.
  
In your new GitHub repo, head over to `.github/workflows/CI.yml`. This file describes the workflow for testing new push or pull-request actions on the repo.
Currently, it is configured to build the plugin and run all the tests in it.

You may need to alter the dependencies required by your new plugin.
Also, the **OpenSearch version** in the `Build OpenSearch` and in the `Build and Run Tests` steps should match your plugins version in the `build.gradle` file.

To view more complex CI examples you may want to checkout the workflows in official OpenSearch plugins, such as [anomaly-detection](https://github.com/opensearch-project/anomaly-detection/blob/main/.github/workflows/CI.yml).

## License
This code is licensed under the Apache 2.0 License. See [LICENSE.txt](LICENSE.txt).

## Copyright
Copyright OpenSearch Contributors. See [NOTICE](NOTICE.txt) for details.