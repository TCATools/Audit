# -*- coding: utf-8 -*-
"""
audit: js/ts 依赖分析工具
功能: 代码分析
用法: python3 main.py
"""


import os
import json
import subprocess

serverity_map = {
    "info": "VUL_INFO",
    "low": "VUL_INFO",
    "moderate": "VUL_WARN",
    "high": "VUL_ERROR",
    "critical": "VUL_ERROR"
}

class Yarn(object):
    def __init__(self, source_dir):
        self.output_path = "yarn_results.json"
        self.lock_file = "yarn.lock"
        self.source_dir = source_dir

    def check(self):
        yarn_file = os.path.join(self.source_dir, self.lock_file)
        if not os.path.exists(yarn_file):
            print("yarn.lock not exists, skip")
            return False
        return True

    def scan(self, rules: list):
        fs = open(self.output_path, "w")
        cmd = self.get_cmd()
        scan_cmd = " ".join(cmd)
        print("[debug] cmd: %s" % scan_cmd)

        subproc = subprocess.Popen(scan_cmd, cwd=self.source_dir, stdout=fs, shell=True)
        subproc.communicate()

        return self.data_handle(rules)

    def get_cmd(self):
        cmd = [
            "yarn",
            "audit",
            "--groups",
            "dependencies",
            "--ignore-scripts",
            "--json"
        ]
        return cmd

    def data_handle(self, rules: list):
        try:
            with open(self.output_path, "r") as fs:
                outputs_data = fs.readlines()
        except:
            print("[error] cannot load yarn outputs: %s" % self.output_path)
            return []

        issues = []
        for line in outputs_data:
            item = json.loads(line)
            if item.get("type", "") == "auditAdvisory":
                issue = {
                    "column": 0,
                    "line": 0,
                    "path": self.lock_file,
                    "refs": [],
                }
                rule = serverity_map.get(item["data"]["advisory"]["severity"], None)
                if (not rule) or (rule not in rules):
                    continue
                issue["rule"] = rule
                issue["msg"] = "%s@%s组件发现漏洞:%s，影响范围为%s，请尽快升级到fixed版本:%s" % (
                    item["data"]["advisory"]["module_name"],
                    item["data"]["advisory"]["findings"][0]["version"],
                    item["data"]["advisory"]["title"],
                    item["data"]["advisory"]["vulnerable_versions"],
                    item["data"]["advisory"]["patched_versions"],
                )
                issues.append(issue)
        return issues

class Npm(object):
    def __init__(self, source_dir):
        self.output_path = "npm_results.json"
        self.lock_file = "package-lock.json"
        self.package_file = "package.json"
        self.source_dir = source_dir

        version = os.environ.get("NPM_VERSION", "v9.8.1")
        self.old_version = version == "v6.14.16"

    def check(self):
        lock_file = os.path.join(self.source_dir, self.lock_file)
        package_file = os.path.join(self.source_dir, self.package_file)
        if not os.path.exists(lock_file) or (self.old_version and not os.path.exists(package_file)):
            print("package-lock.json not exists, skip")
            return False
        return True

    def scan(self, rules: list):
        fs = open(self.output_path, "w")
        cmd = self.get_cmd()
        scan_cmd = " ".join(cmd)
        print("[debug] cmd: %s" % scan_cmd)

        subproc = subprocess.Popen(scan_cmd, cwd=self.source_dir, stdout=fs, shell=True)
        subproc.communicate()

        return self.data_handle(rules)

    def get_cmd(self):
        if self.old_version:
            cmd = [
                "npm-6",
                "audit",
                "--production",
                "--json"
            ]
        else:
            cmd = [
                "npm",
                "audit",
                "--omit=dev",
                "--ignore-scripts",
                "--json"
            ]
        return cmd

    def data_handle(self, rules: list):
        try:
            with open(self.output_path, "r") as fs:
                outputs_data = json.load(fs)
        except:
            print("[error] cannot load yarn outputs: %s" % self.output_path)
            return []

        issues = []
        if self.old_version:
            if "advisories" not in outputs_data:
                print("[error] outputs: %s" % outputs_data)
                return []
            for _, item in outputs_data["advisories"].items():
                issue = {
                    "column": 0,
                    "line": 0,
                    "path": self.lock_file,
                    "refs": [],
                }
                rule = serverity_map.get(item["severity"], None)
                if (not rule) or (rule not in rules):
                    continue
                issue["rule"] = rule
                issue["msg"] = "%s@%s组件发现漏洞:%s，影响范围为%s，请尽快升级到fixed版本:%s" % (
                    item["module_name"],
                    item["findings"][0]["version"],
                    item["title"],
                    item["vulnerable_versions"],
                    item["patched_versions"],
                )
                issues.append(issue)
        else:
            if "vulnerabilities" not in outputs_data:
                print("[error] outputs: %s" % outputs_data)
                return []
            for _, item in outputs_data["vulnerabilities"].items():
                issue = {
                    "column": 0,
                    "line": 0,
                    "path": self.lock_file,
                    "refs": [],
                }
                rule = serverity_map.get(item["severity"], None)
                if (not rule) or (rule not in rules):
                    continue
                issue["rule"] = rule
                via = item.get("via", [])
                title = via[0].get("title", "") if via and isinstance(via[0], dict) else ""
                issue["msg"] = "%s@%s组件发现漏洞:%s，影响范围为%s，请尽快升级到fixed版本" % (
                    item["name"],
                    item["range"],
                    title,
                    item["range"]
                )
                issues.append(issue)
        return issues

class Audit(object):
    def __get_task_params(self):
        """获取需要任务参数
        :return:
        """
        task_request_file = os.environ.get("TASK_REQUEST")
        # task_request_file = "task_request.json"
        with open(task_request_file, 'r') as rf:
            task_request = json.load(rf)
        task_params = task_request["task_params"]

        return task_params

    def run(self):
        """
        :return:
        """
        # 代码目录直接从环境变量获取
        source_dir = os.environ.get("SOURCE_DIR", None)
        print("[debug] source_dir: %s" % source_dir)
        # 其他参数从task_request.json文件获取
        task_params = self.__get_task_params()
        # 环境变量
        envs = task_params["envs"]
        print("[debug] envs: %s" % envs)
        # 规则
        rules = task_params["rules"]

        result = []

        yarn_client = Yarn(source_dir)
        if yarn_client.check():
            result.extend(yarn_client.scan(rules))

        npm_client = Npm(source_dir)
        if npm_client.check():
            result.extend(npm_client.scan(rules))

        with open("result.json", "w") as fp:
            json.dump(result, fp, indent=2, ensure_ascii=False)

if __name__ == '__main__':
    print("-- start run tool ...")
    Audit().run()
    print("-- end ...")
