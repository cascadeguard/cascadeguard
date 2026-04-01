from pkgutil import extend_path
__path__ = extend_path(__path__, __name__)

import abc
import builtins
import datetime
import enum
import typing

import jsii
import publication
import typing_extensions

import typeguard
from importlib.metadata import version as _metadata_package_version
TYPEGUARD_MAJOR_VERSION = int(_metadata_package_version('typeguard').split('.')[0])

def check_type(argname: str, value: object, expected_type: typing.Any) -> typing.Any:
    if TYPEGUARD_MAJOR_VERSION <= 2:
        return typeguard.check_type(argname=argname, value=value, expected_type=expected_type) # type:ignore
    else:
        if isinstance(value, jsii._reference_map.InterfaceDynamicProxy): # pyright: ignore [reportAttributeAccessIssue]
           pass
        else:
            if TYPEGUARD_MAJOR_VERSION == 3:
                typeguard.config.collection_check_strategy = typeguard.CollectionCheckStrategy.ALL_ITEMS # type:ignore
                typeguard.check_type(value=value, expected_type=expected_type) # type:ignore
            else:
                typeguard.check_type(value=value, expected_type=expected_type, collection_check_strategy=typeguard.CollectionCheckStrategy.ALL_ITEMS) # type:ignore

from ._jsii import *

import cdk8s as _cdk8s_d3d9af27
import constructs as _constructs_77d1e7e8


class Warehouse(
    _cdk8s_d3d9af27.ApiObject,
    metaclass=jsii.JSIIMeta,
    jsii_type="ioakuitykargo.Warehouse",
):
    '''Warehouse is a source of Freight.

    :schema: Warehouse
    '''

    def __init__(
        self,
        scope: _constructs_77d1e7e8.Construct,
        id: builtins.str,
        *,
        spec: typing.Union["WarehouseSpec", typing.Dict[builtins.str, typing.Any]],
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Defines a "Warehouse" API object.

        :param scope: the scope in which to define this object.
        :param id: a scope-local name for the object.
        :param spec: Spec describes sources of artifacts.
        :param metadata: 
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__0d3595958d9c70a14819fa9e779252cdc2825a9ab5a9375d18eeebb7fcd0eb1b)
            check_type(argname="argument scope", value=scope, expected_type=type_hints["scope"])
            check_type(argname="argument id", value=id, expected_type=type_hints["id"])
        props = WarehouseProps(spec=spec, metadata=metadata)

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="manifest")
    @builtins.classmethod
    def manifest(
        cls,
        *,
        spec: typing.Union["WarehouseSpec", typing.Dict[builtins.str, typing.Any]],
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> typing.Any:
        '''Renders a Kubernetes manifest for "Warehouse".

        This can be used to inline resource manifests inside other objects (e.g. as templates).

        :param spec: Spec describes sources of artifacts.
        :param metadata: 
        '''
        props = WarehouseProps(spec=spec, metadata=metadata)

        return typing.cast(typing.Any, jsii.sinvoke(cls, "manifest", [props]))

    @jsii.member(jsii_name="toJson")
    def to_json(self) -> typing.Any:
        '''Renders the object to Kubernetes JSON.'''
        return typing.cast(typing.Any, jsii.invoke(self, "toJson", []))

    @jsii.python.classproperty
    @jsii.member(jsii_name="GVK")
    def GVK(cls) -> _cdk8s_d3d9af27.GroupVersionKind:
        '''Returns the apiVersion and kind for "Warehouse".'''
        return typing.cast(_cdk8s_d3d9af27.GroupVersionKind, jsii.sget(cls, "GVK"))


@jsii.data_type(
    jsii_type="ioakuitykargo.WarehouseProps",
    jsii_struct_bases=[],
    name_mapping={"spec": "spec", "metadata": "metadata"},
)
class WarehouseProps:
    def __init__(
        self,
        *,
        spec: typing.Union["WarehouseSpec", typing.Dict[builtins.str, typing.Any]],
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Warehouse is a source of Freight.

        :param spec: Spec describes sources of artifacts.
        :param metadata: 

        :schema: Warehouse
        '''
        if isinstance(spec, dict):
            spec = WarehouseSpec(**spec)
        if isinstance(metadata, dict):
            metadata = _cdk8s_d3d9af27.ApiObjectMetadata(**metadata)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__5d007700434580cb9bba6040b438584f6f8aa3141c2d26b402b125ffaaa2e43f)
            check_type(argname="argument spec", value=spec, expected_type=type_hints["spec"])
            check_type(argname="argument metadata", value=metadata, expected_type=type_hints["metadata"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "spec": spec,
        }
        if metadata is not None:
            self._values["metadata"] = metadata

    @builtins.property
    def spec(self) -> "WarehouseSpec":
        '''Spec describes sources of artifacts.

        :schema: Warehouse#spec
        '''
        result = self._values.get("spec")
        assert result is not None, "Required property 'spec' is missing"
        return typing.cast("WarehouseSpec", result)

    @builtins.property
    def metadata(self) -> typing.Optional[_cdk8s_d3d9af27.ApiObjectMetadata]:
        '''
        :schema: Warehouse#metadata
        '''
        result = self._values.get("metadata")
        return typing.cast(typing.Optional[_cdk8s_d3d9af27.ApiObjectMetadata], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "WarehouseProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioakuitykargo.WarehouseSpec",
    jsii_struct_bases=[],
    name_mapping={
        "interval": "interval",
        "subscriptions": "subscriptions",
        "freight_creation_criteria": "freightCreationCriteria",
        "freight_creation_policy": "freightCreationPolicy",
        "shard": "shard",
    },
)
class WarehouseSpec:
    def __init__(
        self,
        *,
        interval: builtins.str,
        subscriptions: typing.Sequence[typing.Union["WarehouseSpecSubscriptions", typing.Dict[builtins.str, typing.Any]]],
        freight_creation_criteria: typing.Optional[typing.Union["WarehouseSpecFreightCreationCriteria", typing.Dict[builtins.str, typing.Any]]] = None,
        freight_creation_policy: typing.Optional["WarehouseSpecFreightCreationPolicy"] = None,
        shard: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Spec describes sources of artifacts.

        :param interval: Interval is the reconciliation interval for this Warehouse. On each reconciliation, the Warehouse will discover new artifacts and optionally produce new Freight. This field is optional. When left unspecified, the field is implicitly treated as if its value were "5m0s".
        :param subscriptions: Subscriptions describes sources of artifacts to be included in Freight produced by this Warehouse.
        :param freight_creation_criteria: FreightCreationCriteria defines criteria that must be satisfied for Freight to be created automatically from new artifacts following discovery. This field has no effect when the FreightCreationPolicy is ``Manual``.
        :param freight_creation_policy: FreightCreationPolicy describes how Freight is created by this Warehouse. This field is optional. When left unspecified, the field is implicitly treated as if its value were "Automatic". Accepted values: - "Automatic": New Freight is created automatically when any new artifact is discovered. - "Manual": New Freight is never created automatically.
        :param shard: Shard is the name of the shard that this Warehouse belongs to. This is an optional field. If not specified, the Warehouse will belong to the default shard. A defaulting webhook will sync this field with the value of the kargo.akuity.io/shard label. When the shard label is not present or differs from the value of this field, the defaulting webhook will set the label to the value of this field. If the shard label is present and this field is empty, the defaulting webhook will set the value of this field to the value of the shard label.

        :schema: WarehouseSpec
        '''
        if isinstance(freight_creation_criteria, dict):
            freight_creation_criteria = WarehouseSpecFreightCreationCriteria(**freight_creation_criteria)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__96b70e86277b06f8fe986bd2bd52c99fd27fedc6a8bc8f12fd8374fba67ba7bc)
            check_type(argname="argument interval", value=interval, expected_type=type_hints["interval"])
            check_type(argname="argument subscriptions", value=subscriptions, expected_type=type_hints["subscriptions"])
            check_type(argname="argument freight_creation_criteria", value=freight_creation_criteria, expected_type=type_hints["freight_creation_criteria"])
            check_type(argname="argument freight_creation_policy", value=freight_creation_policy, expected_type=type_hints["freight_creation_policy"])
            check_type(argname="argument shard", value=shard, expected_type=type_hints["shard"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "interval": interval,
            "subscriptions": subscriptions,
        }
        if freight_creation_criteria is not None:
            self._values["freight_creation_criteria"] = freight_creation_criteria
        if freight_creation_policy is not None:
            self._values["freight_creation_policy"] = freight_creation_policy
        if shard is not None:
            self._values["shard"] = shard

    @builtins.property
    def interval(self) -> builtins.str:
        '''Interval is the reconciliation interval for this Warehouse.

        On each
        reconciliation, the Warehouse will discover new artifacts and optionally
        produce new Freight. This field is optional. When left unspecified, the
        field is implicitly treated as if its value were "5m0s".

        :schema: WarehouseSpec#interval
        '''
        result = self._values.get("interval")
        assert result is not None, "Required property 'interval' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def subscriptions(self) -> typing.List["WarehouseSpecSubscriptions"]:
        '''Subscriptions describes sources of artifacts to be included in Freight produced by this Warehouse.

        :schema: WarehouseSpec#subscriptions
        '''
        result = self._values.get("subscriptions")
        assert result is not None, "Required property 'subscriptions' is missing"
        return typing.cast(typing.List["WarehouseSpecSubscriptions"], result)

    @builtins.property
    def freight_creation_criteria(
        self,
    ) -> typing.Optional["WarehouseSpecFreightCreationCriteria"]:
        '''FreightCreationCriteria defines criteria that must be satisfied for Freight to be created automatically from new artifacts following discovery.

        This
        field has no effect when the FreightCreationPolicy is ``Manual``.

        :schema: WarehouseSpec#freightCreationCriteria
        '''
        result = self._values.get("freight_creation_criteria")
        return typing.cast(typing.Optional["WarehouseSpecFreightCreationCriteria"], result)

    @builtins.property
    def freight_creation_policy(
        self,
    ) -> typing.Optional["WarehouseSpecFreightCreationPolicy"]:
        '''FreightCreationPolicy describes how Freight is created by this Warehouse.

        This field is optional. When left unspecified, the field is implicitly
        treated as if its value were "Automatic".

        Accepted values:

        - "Automatic": New Freight is created automatically when any new artifact
          is discovered.
        - "Manual": New Freight is never created automatically.

        :schema: WarehouseSpec#freightCreationPolicy
        '''
        result = self._values.get("freight_creation_policy")
        return typing.cast(typing.Optional["WarehouseSpecFreightCreationPolicy"], result)

    @builtins.property
    def shard(self) -> typing.Optional[builtins.str]:
        '''Shard is the name of the shard that this Warehouse belongs to.

        This is an
        optional field. If not specified, the Warehouse will belong to the default
        shard. A defaulting webhook will sync this field with the value of the
        kargo.akuity.io/shard label. When the shard label is not present or differs
        from the value of this field, the defaulting webhook will set the label to
        the value of this field. If the shard label is present and this field is
        empty, the defaulting webhook will set the value of this field to the value
        of the shard label.

        :schema: WarehouseSpec#shard
        '''
        result = self._values.get("shard")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "WarehouseSpec(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioakuitykargo.WarehouseSpecFreightCreationCriteria",
    jsii_struct_bases=[],
    name_mapping={"expression": "expression"},
)
class WarehouseSpecFreightCreationCriteria:
    def __init__(self, *, expression: typing.Optional[builtins.str] = None) -> None:
        '''FreightCreationCriteria defines criteria that must be satisfied for Freight to be created automatically from new artifacts following discovery.

        This
        field has no effect when the FreightCreationPolicy is ``Manual``.

        :param expression: Expression is an expr-lang expression that must evaluate to true for Freight to be created automatically from new artifacts following discovery.

        :schema: WarehouseSpecFreightCreationCriteria
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__5b75c0982383506164595bf82f420954fa4526e23ee36bebc0c68394ec12b107)
            check_type(argname="argument expression", value=expression, expected_type=type_hints["expression"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if expression is not None:
            self._values["expression"] = expression

    @builtins.property
    def expression(self) -> typing.Optional[builtins.str]:
        '''Expression is an expr-lang expression that must evaluate to true for Freight to be created automatically from new artifacts following discovery.

        :schema: WarehouseSpecFreightCreationCriteria#expression
        '''
        result = self._values.get("expression")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "WarehouseSpecFreightCreationCriteria(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="ioakuitykargo.WarehouseSpecFreightCreationPolicy")
class WarehouseSpecFreightCreationPolicy(enum.Enum):
    '''FreightCreationPolicy describes how Freight is created by this Warehouse.

    This field is optional. When left unspecified, the field is implicitly
    treated as if its value were "Automatic".

    Accepted values:

    - "Automatic": New Freight is created automatically when any new artifact
      is discovered.
    - "Manual": New Freight is never created automatically.

    :schema: WarehouseSpecFreightCreationPolicy
    '''

    AUTOMATIC = "AUTOMATIC"
    '''Automatic.'''
    MANUAL = "MANUAL"
    '''Manual.'''


@jsii.data_type(
    jsii_type="ioakuitykargo.WarehouseSpecSubscriptions",
    jsii_struct_bases=[],
    name_mapping={"chart": "chart", "git": "git", "image": "image"},
)
class WarehouseSpecSubscriptions:
    def __init__(
        self,
        *,
        chart: typing.Optional[typing.Union["WarehouseSpecSubscriptionsChart", typing.Dict[builtins.str, typing.Any]]] = None,
        git: typing.Optional[typing.Union["WarehouseSpecSubscriptionsGit", typing.Dict[builtins.str, typing.Any]]] = None,
        image: typing.Optional[typing.Union["WarehouseSpecSubscriptionsImage", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''RepoSubscription describes a subscription to ONE OF a Git repository, a container image repository, or a Helm chart repository.

        :param chart: Chart describes a subscription to a Helm chart repository.
        :param git: Git describes a subscriptions to a Git repository.
        :param image: Image describes a subscription to container image repository.

        :schema: WarehouseSpecSubscriptions
        '''
        if isinstance(chart, dict):
            chart = WarehouseSpecSubscriptionsChart(**chart)
        if isinstance(git, dict):
            git = WarehouseSpecSubscriptionsGit(**git)
        if isinstance(image, dict):
            image = WarehouseSpecSubscriptionsImage(**image)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__912102abedf9e7da0e2c7cba52a63d1730862434276e401aea3317ff23eee00f)
            check_type(argname="argument chart", value=chart, expected_type=type_hints["chart"])
            check_type(argname="argument git", value=git, expected_type=type_hints["git"])
            check_type(argname="argument image", value=image, expected_type=type_hints["image"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if chart is not None:
            self._values["chart"] = chart
        if git is not None:
            self._values["git"] = git
        if image is not None:
            self._values["image"] = image

    @builtins.property
    def chart(self) -> typing.Optional["WarehouseSpecSubscriptionsChart"]:
        '''Chart describes a subscription to a Helm chart repository.

        :schema: WarehouseSpecSubscriptions#chart
        '''
        result = self._values.get("chart")
        return typing.cast(typing.Optional["WarehouseSpecSubscriptionsChart"], result)

    @builtins.property
    def git(self) -> typing.Optional["WarehouseSpecSubscriptionsGit"]:
        '''Git describes a subscriptions to a Git repository.

        :schema: WarehouseSpecSubscriptions#git
        '''
        result = self._values.get("git")
        return typing.cast(typing.Optional["WarehouseSpecSubscriptionsGit"], result)

    @builtins.property
    def image(self) -> typing.Optional["WarehouseSpecSubscriptionsImage"]:
        '''Image describes a subscription to container image repository.

        :schema: WarehouseSpecSubscriptions#image
        '''
        result = self._values.get("image")
        return typing.cast(typing.Optional["WarehouseSpecSubscriptionsImage"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "WarehouseSpecSubscriptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioakuitykargo.WarehouseSpecSubscriptionsChart",
    jsii_struct_bases=[],
    name_mapping={
        "repo_url": "repoUrl",
        "discovery_limit": "discoveryLimit",
        "name": "name",
        "semver_constraint": "semverConstraint",
    },
)
class WarehouseSpecSubscriptionsChart:
    def __init__(
        self,
        *,
        repo_url: builtins.str,
        discovery_limit: typing.Optional[jsii.Number] = None,
        name: typing.Optional[builtins.str] = None,
        semver_constraint: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Chart describes a subscription to a Helm chart repository.

        :param repo_url: RepoURL specifies the URL of a Helm chart repository. It may be a classic chart repository (using HTTP/S) OR a repository within an OCI registry. Classic chart repositories can contain differently named charts. When this field points to such a repository, the Name field MUST also be used to specify the name of the desired chart within that repository. In the case of a repository within an OCI registry, the URL implicitly points to a specific chart and the Name field MUST NOT be used. The RepoURL field is required.
        :param discovery_limit: DiscoveryLimit is an optional limit on the number of chart versions that can be discovered for this subscription. The limit is applied after filtering charts based on the SemverConstraint field. When left unspecified, the field is implicitly treated as if its value were "20". The upper limit for this field is 100.
        :param name: Name specifies the name of a Helm chart to subscribe to within a classic chart repository specified by the RepoURL field. This field is required when the RepoURL field points to a classic chart repository and MUST otherwise be empty.
        :param semver_constraint: SemverConstraint specifies constraints on what new chart versions are permissible. This field is optional. When left unspecified, there will be no constraints, which means the latest version of the chart will always be used. Care should be taken with leaving this field unspecified, as it can lead to the unanticipated rollout of breaking changes. More info: https://github.com/masterminds/semver#checking-version-constraints

        :schema: WarehouseSpecSubscriptionsChart
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__874448dfb3f36813a80705d1af939222bdff810e86b791ce0d52faacf3ecd770)
            check_type(argname="argument repo_url", value=repo_url, expected_type=type_hints["repo_url"])
            check_type(argname="argument discovery_limit", value=discovery_limit, expected_type=type_hints["discovery_limit"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument semver_constraint", value=semver_constraint, expected_type=type_hints["semver_constraint"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "repo_url": repo_url,
        }
        if discovery_limit is not None:
            self._values["discovery_limit"] = discovery_limit
        if name is not None:
            self._values["name"] = name
        if semver_constraint is not None:
            self._values["semver_constraint"] = semver_constraint

    @builtins.property
    def repo_url(self) -> builtins.str:
        '''RepoURL specifies the URL of a Helm chart repository.

        It may be a classic
        chart repository (using HTTP/S) OR a repository within an OCI registry.
        Classic chart repositories can contain differently named charts. When this
        field points to such a repository, the Name field MUST also be used
        to specify the name of the desired chart within that repository. In the
        case of a repository within an OCI registry, the URL implicitly points to
        a specific chart and the Name field MUST NOT be used. The RepoURL field is
        required.

        :schema: WarehouseSpecSubscriptionsChart#repoURL
        '''
        result = self._values.get("repo_url")
        assert result is not None, "Required property 'repo_url' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def discovery_limit(self) -> typing.Optional[jsii.Number]:
        '''DiscoveryLimit is an optional limit on the number of chart versions that can be discovered for this subscription.

        The limit is applied after
        filtering charts based on the SemverConstraint field.
        When left unspecified, the field is implicitly treated as if its value
        were "20". The upper limit for this field is 100.

        :schema: WarehouseSpecSubscriptionsChart#discoveryLimit
        '''
        result = self._values.get("discovery_limit")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''Name specifies the name of a Helm chart to subscribe to within a classic chart repository specified by the RepoURL field.

        This field is required
        when the RepoURL field points to a classic chart repository and MUST
        otherwise be empty.

        :schema: WarehouseSpecSubscriptionsChart#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def semver_constraint(self) -> typing.Optional[builtins.str]:
        '''SemverConstraint specifies constraints on what new chart versions are permissible.

        This field is optional. When left unspecified, there will be
        no constraints, which means the latest version of the chart will always be
        used. Care should be taken with leaving this field unspecified, as it can
        lead to the unanticipated rollout of breaking changes.
        More info: https://github.com/masterminds/semver#checking-version-constraints

        :schema: WarehouseSpecSubscriptionsChart#semverConstraint
        '''
        result = self._values.get("semver_constraint")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "WarehouseSpecSubscriptionsChart(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioakuitykargo.WarehouseSpecSubscriptionsGit",
    jsii_struct_bases=[],
    name_mapping={
        "repo_url": "repoUrl",
        "strict_semvers": "strictSemvers",
        "allow_tags": "allowTags",
        "branch": "branch",
        "commit_selection_strategy": "commitSelectionStrategy",
        "discovery_limit": "discoveryLimit",
        "exclude_paths": "excludePaths",
        "expression_filter": "expressionFilter",
        "ignore_tags": "ignoreTags",
        "include_paths": "includePaths",
        "insecure_skip_tls_verify": "insecureSkipTlsVerify",
        "semver_constraint": "semverConstraint",
    },
)
class WarehouseSpecSubscriptionsGit:
    def __init__(
        self,
        *,
        repo_url: builtins.str,
        strict_semvers: builtins.bool,
        allow_tags: typing.Optional[builtins.str] = None,
        branch: typing.Optional[builtins.str] = None,
        commit_selection_strategy: typing.Optional["WarehouseSpecSubscriptionsGitCommitSelectionStrategy"] = None,
        discovery_limit: typing.Optional[jsii.Number] = None,
        exclude_paths: typing.Optional[typing.Sequence[builtins.str]] = None,
        expression_filter: typing.Optional[builtins.str] = None,
        ignore_tags: typing.Optional[typing.Sequence[builtins.str]] = None,
        include_paths: typing.Optional[typing.Sequence[builtins.str]] = None,
        insecure_skip_tls_verify: typing.Optional[builtins.bool] = None,
        semver_constraint: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Git describes a subscriptions to a Git repository.

        :param repo_url: URL is the repository's URL. This is a required field.
        :param strict_semvers: StrictSemvers specifies whether only "strict" semver tags should be considered. A "strict" semver tag is one containing ALL of major, minor, and patch version components. This is enabled by default, but only has any effect when the CommitSelectionStrategy is SemVer. This should be disabled cautiously, as it creates the potential for any tag containing numeric characters only to be mistaken for a semver string containing the major version number only.
        :param allow_tags: AllowTags is a regular expression that can optionally be used to limit the tags that are considered in determining the newest commit of interest. The value in this field only has any effect when the CommitSelectionStrategy is Lexical, NewestTag, or SemVer. This field is optional.
        :param branch: Branch references a particular branch of the repository. The value in this field only has any effect when the CommitSelectionStrategy is NewestFromBranch or left unspecified (which is implicitly the same as NewestFromBranch). This field is optional. When left unspecified, (and the CommitSelectionStrategy is NewestFromBranch or unspecified), the subscription is implicitly to the repository's default branch.
        :param commit_selection_strategy: CommitSelectionStrategy specifies the rules for how to identify the newest commit of interest in the repository specified by the RepoURL field. This field is optional. When left unspecified, the field is implicitly treated as if its value were "NewestFromBranch". Accepted values: - "NewestFromBranch": Selects the latest commit on the branch specified by the Branch field or the default branch if none is specified. This is the default strategy. - "SemVer": Selects the commit referenced by the semantically greatest tag. The SemverConstraint field can optionally be used to narrow the set of tags eligible for selection. - "Lexical": Selects the commit referenced by the lexicographically greatest tag. Useful when tags embed a *leading* date or timestamp. The AllowTags and IgnoreTags fields can optionally be used to narrow the set of tags eligible for selection. - "NewestTag": Selects the commit referenced by the most recently created tag. The AllowTags and IgnoreTags fields can optionally be used to narrow the set of tags eligible for selection.
        :param discovery_limit: DiscoveryLimit is an optional limit on the number of commits that can be discovered for this subscription. The limit is applied after filtering commits based on the AllowTags and IgnoreTags fields. When left unspecified, the field is implicitly treated as if its value were "20". The upper limit for this field is 100.
        :param exclude_paths: ExcludePaths is a list of selectors that designate paths in the repository that should NOT trigger the production of new Freight when changes are detected therein. When specified, changes in the identified paths will not trigger Freight production. When not specified, paths that should trigger Freight production will be defined solely by IncludePaths. Selectors may be defined using: 1. Exact paths to files or directories (ex. "charts/foo") 2. Glob patterns (prefix the pattern with "glob:"; ex. "glob:*.yaml") 3. Regular expressions (prefix the pattern with "regex:" or "regexp:"; ex. "regexp:^.*.yaml$") Paths selected by IncludePaths may be unselected by ExcludePaths. This is a useful method for including a broad set of paths and then excluding a subset of them.
        :param expression_filter: ExpressionFilter is an expression that can optionally be used to limit the commits or tags that are considered in determining the newest commit of interest based on their metadata. For commit-based strategies (NewestFromBranch), the filter applies to commits and has access to commit metadata variables. For tag-based strategies (Lexical, NewestTag, SemVer), the filter applies to tags and has access to tag metadata variables. The filter is applied after AllowTags, IgnoreTags, and SemverConstraint fields. The expression should be a valid expr-lang expression that evaluates to true or false. When the expression evaluates to true, the commit/tag is included in the set that is considered. When the expression evaluates to false, the commit/tag is excluded. Available variables depend on the CommitSelectionStrategy: For NewestFromBranch (commit filtering): - ``id``: The ID (sha) of the commit. - ``commitDate``: The commit date of the commit. - ``author``: The author of the commit message, in the format "Name ". - ``committer``: The person who committed the commit, in the format "Name ". - ``subject``: The subject (first line) of the commit message. For Lexical, NewestTag, SemVer (tag filtering): - ``tag``: The name of the tag. - ``id``: The ID (sha) of the commit associated with the tag. - ``creatorDate``: The creation date of an annotated tag, or the commit date of a lightweight tag. - ``author``: The author of the commit message associated with the tag, in the format "Name ". - ``committer``: The person who committed the commit associated with the tag, in the format "Name ". - ``subject``: The subject (first line) of the commit message associated with the tag. - ``tagger``: The person who created the tag, in the format "Name ". Only available for annotated tags. - ``annotation``: The subject (first line) of the tag annotation. Only available for annotated tags. Refer to the expr-lang documentation for more details on syntax and capabilities of the expression language: https://expr-lang.org.
        :param ignore_tags: IgnoreTags is a list of tags that must be ignored when determining the newest commit of interest. No regular expressions or glob patterns are supported yet. The value in this field only has any effect when the CommitSelectionStrategy is Lexical, NewestTag, or SemVer. This field is optional.
        :param include_paths: IncludePaths is a list of selectors that designate paths in the repository that should trigger the production of new Freight when changes are detected therein. When specified, only changes in the identified paths will trigger Freight production. When not specified, changes in any path will trigger Freight production. Selectors may be defined using: 1. Exact paths to files or directories (ex. "charts/foo") 2. Glob patterns (prefix the pattern with "glob:"; ex. "glob:*.yaml") 3. Regular expressions (prefix the pattern with "regex:" or "regexp:"; ex. "regexp:^.*.yaml$") Paths selected by IncludePaths may be unselected by ExcludePaths. This is a useful method for including a broad set of paths and then excluding a subset of them.
        :param insecure_skip_tls_verify: InsecureSkipTLSVerify specifies whether certificate verification errors should be ignored when connecting to the repository. This should be enabled only with great caution.
        :param semver_constraint: SemverConstraint specifies constraints on what new tagged commits are considered in determining the newest commit of interest. The value in this field only has any effect when the CommitSelectionStrategy is SemVer. This field is optional. When left unspecified, there will be no constraints, which means the latest semantically tagged commit will always be used. Care should be taken with leaving this field unspecified, as it can lead to the unanticipated rollout of breaking changes.

        :schema: WarehouseSpecSubscriptionsGit
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__6299d41dd10d1abd16222f108336988c4bfa9bcd6ba16fb5e4f4574778624074)
            check_type(argname="argument repo_url", value=repo_url, expected_type=type_hints["repo_url"])
            check_type(argname="argument strict_semvers", value=strict_semvers, expected_type=type_hints["strict_semvers"])
            check_type(argname="argument allow_tags", value=allow_tags, expected_type=type_hints["allow_tags"])
            check_type(argname="argument branch", value=branch, expected_type=type_hints["branch"])
            check_type(argname="argument commit_selection_strategy", value=commit_selection_strategy, expected_type=type_hints["commit_selection_strategy"])
            check_type(argname="argument discovery_limit", value=discovery_limit, expected_type=type_hints["discovery_limit"])
            check_type(argname="argument exclude_paths", value=exclude_paths, expected_type=type_hints["exclude_paths"])
            check_type(argname="argument expression_filter", value=expression_filter, expected_type=type_hints["expression_filter"])
            check_type(argname="argument ignore_tags", value=ignore_tags, expected_type=type_hints["ignore_tags"])
            check_type(argname="argument include_paths", value=include_paths, expected_type=type_hints["include_paths"])
            check_type(argname="argument insecure_skip_tls_verify", value=insecure_skip_tls_verify, expected_type=type_hints["insecure_skip_tls_verify"])
            check_type(argname="argument semver_constraint", value=semver_constraint, expected_type=type_hints["semver_constraint"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "repo_url": repo_url,
            "strict_semvers": strict_semvers,
        }
        if allow_tags is not None:
            self._values["allow_tags"] = allow_tags
        if branch is not None:
            self._values["branch"] = branch
        if commit_selection_strategy is not None:
            self._values["commit_selection_strategy"] = commit_selection_strategy
        if discovery_limit is not None:
            self._values["discovery_limit"] = discovery_limit
        if exclude_paths is not None:
            self._values["exclude_paths"] = exclude_paths
        if expression_filter is not None:
            self._values["expression_filter"] = expression_filter
        if ignore_tags is not None:
            self._values["ignore_tags"] = ignore_tags
        if include_paths is not None:
            self._values["include_paths"] = include_paths
        if insecure_skip_tls_verify is not None:
            self._values["insecure_skip_tls_verify"] = insecure_skip_tls_verify
        if semver_constraint is not None:
            self._values["semver_constraint"] = semver_constraint

    @builtins.property
    def repo_url(self) -> builtins.str:
        '''URL is the repository's URL.

        This is a required field.

        :schema: WarehouseSpecSubscriptionsGit#repoURL
        '''
        result = self._values.get("repo_url")
        assert result is not None, "Required property 'repo_url' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def strict_semvers(self) -> builtins.bool:
        '''StrictSemvers specifies whether only "strict" semver tags should be considered.

        A "strict" semver tag is one containing ALL of major, minor,
        and patch version components. This is enabled by default, but only has any
        effect when the CommitSelectionStrategy is SemVer. This should be disabled
        cautiously, as it creates the potential for any tag containing numeric
        characters only to be mistaken for a semver string containing the major
        version number only.

        :schema: WarehouseSpecSubscriptionsGit#strictSemvers
        '''
        result = self._values.get("strict_semvers")
        assert result is not None, "Required property 'strict_semvers' is missing"
        return typing.cast(builtins.bool, result)

    @builtins.property
    def allow_tags(self) -> typing.Optional[builtins.str]:
        '''AllowTags is a regular expression that can optionally be used to limit the tags that are considered in determining the newest commit of interest.

        The
        value in this field only has any effect when the CommitSelectionStrategy is
        Lexical, NewestTag, or SemVer. This field is optional.

        :schema: WarehouseSpecSubscriptionsGit#allowTags
        '''
        result = self._values.get("allow_tags")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def branch(self) -> typing.Optional[builtins.str]:
        '''Branch references a particular branch of the repository.

        The value in this
        field only has any effect when the CommitSelectionStrategy is
        NewestFromBranch or left unspecified (which is implicitly the same as
        NewestFromBranch). This field is optional. When left unspecified, (and the
        CommitSelectionStrategy is NewestFromBranch or unspecified), the
        subscription is implicitly to the repository's default branch.

        :schema: WarehouseSpecSubscriptionsGit#branch
        '''
        result = self._values.get("branch")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def commit_selection_strategy(
        self,
    ) -> typing.Optional["WarehouseSpecSubscriptionsGitCommitSelectionStrategy"]:
        '''CommitSelectionStrategy specifies the rules for how to identify the newest commit of interest in the repository specified by the RepoURL field.

        This
        field is optional. When left unspecified, the field is implicitly treated
        as if its value were "NewestFromBranch".

        Accepted values:

        - "NewestFromBranch": Selects the latest commit on the branch specified
          by the Branch field or the default branch if none is specified. This is
          the default strategy.
        - "SemVer": Selects the commit referenced by the semantically greatest
          tag. The SemverConstraint field can optionally be used to narrow the set
          of tags eligible for selection.
        - "Lexical": Selects the commit referenced by the lexicographically
          greatest tag. Useful when tags embed a *leading* date or timestamp. The
          AllowTags and IgnoreTags fields can optionally be used to narrow the set
          of tags eligible for selection.
        - "NewestTag": Selects the commit referenced by the most recently created
          tag. The AllowTags and IgnoreTags fields can optionally be used to
          narrow the set of tags eligible for selection.

        :schema: WarehouseSpecSubscriptionsGit#commitSelectionStrategy
        '''
        result = self._values.get("commit_selection_strategy")
        return typing.cast(typing.Optional["WarehouseSpecSubscriptionsGitCommitSelectionStrategy"], result)

    @builtins.property
    def discovery_limit(self) -> typing.Optional[jsii.Number]:
        '''DiscoveryLimit is an optional limit on the number of commits that can be discovered for this subscription.

        The limit is applied after filtering
        commits based on the AllowTags and IgnoreTags fields.
        When left unspecified, the field is implicitly treated as if its value
        were "20". The upper limit for this field is 100.

        :schema: WarehouseSpecSubscriptionsGit#discoveryLimit
        '''
        result = self._values.get("discovery_limit")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def exclude_paths(self) -> typing.Optional[typing.List[builtins.str]]:
        '''ExcludePaths is a list of selectors that designate paths in the repository that should NOT trigger the production of new Freight when changes are detected therein.

        When specified, changes in the identified paths will not
        trigger Freight production. When not specified, paths that should trigger
        Freight production will be defined solely by IncludePaths. Selectors may be
        defined using:

        1. Exact paths to files or directories (ex. "charts/foo")
        2. Glob patterns (prefix the pattern with "glob:"; ex. "glob:*.yaml")
        3. Regular expressions (prefix the pattern with "regex:" or "regexp:";
           ex. "regexp:^.*.yaml$")
           Paths selected by IncludePaths may be unselected by ExcludePaths. This
           is a useful method for including a broad set of paths and then excluding a
           subset of them.

        :schema: WarehouseSpecSubscriptionsGit#excludePaths
        '''
        result = self._values.get("exclude_paths")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def expression_filter(self) -> typing.Optional[builtins.str]:
        '''ExpressionFilter is an expression that can optionally be used to limit the commits or tags that are considered in determining the newest commit of interest based on their metadata.

        For commit-based strategies (NewestFromBranch), the filter applies to
        commits and has access to commit metadata variables.
        For tag-based strategies (Lexical, NewestTag, SemVer), the filter applies
        to tags and has access to tag metadata variables. The filter is applied
        after AllowTags, IgnoreTags, and SemverConstraint fields.

        The expression should be a valid expr-lang expression that evaluates to
        true or false. When the expression evaluates to true, the commit/tag is
        included in the set that is considered. When the expression evaluates to
        false, the commit/tag is excluded.

        Available variables depend on the CommitSelectionStrategy:

        For NewestFromBranch (commit filtering):

        - ``id``: The ID (sha) of the commit.
        - ``commitDate``: The commit date of the commit.
        - ``author``: The author of the commit message, in the format "Name ".
        - ``committer``: The person who committed the commit, in the format
          "Name ".
        - ``subject``: The subject (first line) of the commit message.

        For Lexical, NewestTag, SemVer (tag filtering):

        - ``tag``: The name of the tag.
        - ``id``: The ID (sha) of the commit associated with the tag.
        - ``creatorDate``: The creation date of an annotated tag, or the commit
          date of a lightweight tag.
        - ``author``: The author of the commit message associated with the tag,
          in the format "Name ".
        - ``committer``: The person who committed the commit associated with the
          tag, in the format "Name ".
        - ``subject``: The subject (first line) of the commit message associated
          with the tag.
        - ``tagger``: The person who created the tag, in the format "Name ".
          Only available for annotated tags.
        - ``annotation``: The subject (first line) of the tag annotation. Only
          available for annotated tags.

        Refer to the expr-lang documentation for more details on syntax and
        capabilities of the expression language: https://expr-lang.org.

        :schema: WarehouseSpecSubscriptionsGit#expressionFilter
        '''
        result = self._values.get("expression_filter")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def ignore_tags(self) -> typing.Optional[typing.List[builtins.str]]:
        '''IgnoreTags is a list of tags that must be ignored when determining the newest commit of interest.

        No regular expressions or glob patterns are
        supported yet. The value in this field only has any effect when the
        CommitSelectionStrategy is Lexical, NewestTag, or SemVer. This field is
        optional.

        :schema: WarehouseSpecSubscriptionsGit#ignoreTags
        '''
        result = self._values.get("ignore_tags")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def include_paths(self) -> typing.Optional[typing.List[builtins.str]]:
        '''IncludePaths is a list of selectors that designate paths in the repository that should trigger the production of new Freight when changes are detected therein.

        When specified, only changes in the identified paths will trigger
        Freight production. When not specified, changes in any path will trigger
        Freight production. Selectors may be defined using:

        1. Exact paths to files or directories (ex. "charts/foo")
        2. Glob patterns (prefix the pattern with "glob:"; ex. "glob:*.yaml")
        3. Regular expressions (prefix the pattern with "regex:" or "regexp:";
           ex. "regexp:^.*.yaml$")

        Paths selected by IncludePaths may be unselected by ExcludePaths. This
        is a useful method for including a broad set of paths and then excluding a
        subset of them.

        :schema: WarehouseSpecSubscriptionsGit#includePaths
        '''
        result = self._values.get("include_paths")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def insecure_skip_tls_verify(self) -> typing.Optional[builtins.bool]:
        '''InsecureSkipTLSVerify specifies whether certificate verification errors should be ignored when connecting to the repository.

        This should be enabled
        only with great caution.

        :schema: WarehouseSpecSubscriptionsGit#insecureSkipTLSVerify
        '''
        result = self._values.get("insecure_skip_tls_verify")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def semver_constraint(self) -> typing.Optional[builtins.str]:
        '''SemverConstraint specifies constraints on what new tagged commits are considered in determining the newest commit of interest.

        The value in this
        field only has any effect when the CommitSelectionStrategy is SemVer. This
        field is optional. When left unspecified, there will be no constraints,
        which means the latest semantically tagged commit will always be used. Care
        should be taken with leaving this field unspecified, as it can lead to the
        unanticipated rollout of breaking changes.

        :schema: WarehouseSpecSubscriptionsGit#semverConstraint
        '''
        result = self._values.get("semver_constraint")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "WarehouseSpecSubscriptionsGit(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(
    jsii_type="ioakuitykargo.WarehouseSpecSubscriptionsGitCommitSelectionStrategy"
)
class WarehouseSpecSubscriptionsGitCommitSelectionStrategy(enum.Enum):
    '''CommitSelectionStrategy specifies the rules for how to identify the newest commit of interest in the repository specified by the RepoURL field.

    This
    field is optional. When left unspecified, the field is implicitly treated
    as if its value were "NewestFromBranch".

    Accepted values:

    - "NewestFromBranch": Selects the latest commit on the branch specified
      by the Branch field or the default branch if none is specified. This is
      the default strategy.
    - "SemVer": Selects the commit referenced by the semantically greatest
      tag. The SemverConstraint field can optionally be used to narrow the set
      of tags eligible for selection.
    - "Lexical": Selects the commit referenced by the lexicographically
      greatest tag. Useful when tags embed a *leading* date or timestamp. The
      AllowTags and IgnoreTags fields can optionally be used to narrow the set
      of tags eligible for selection.
    - "NewestTag": Selects the commit referenced by the most recently created
      tag. The AllowTags and IgnoreTags fields can optionally be used to
      narrow the set of tags eligible for selection.

    :schema: WarehouseSpecSubscriptionsGitCommitSelectionStrategy
    '''

    LEXICAL = "LEXICAL"
    '''Lexical.'''
    NEWEST_FROM_BRANCH = "NEWEST_FROM_BRANCH"
    '''NewestFromBranch.'''
    NEWEST_TAG = "NEWEST_TAG"
    '''NewestTag.'''
    SEM_VER = "SEM_VER"
    '''SemVer.'''


@jsii.data_type(
    jsii_type="ioakuitykargo.WarehouseSpecSubscriptionsImage",
    jsii_struct_bases=[],
    name_mapping={
        "repo_url": "repoUrl",
        "strict_semvers": "strictSemvers",
        "allow_tags": "allowTags",
        "constraint": "constraint",
        "discovery_limit": "discoveryLimit",
        "ignore_tags": "ignoreTags",
        "image_selection_strategy": "imageSelectionStrategy",
        "insecure_skip_tls_verify": "insecureSkipTlsVerify",
        "platform": "platform",
        "semver_constraint": "semverConstraint",
    },
)
class WarehouseSpecSubscriptionsImage:
    def __init__(
        self,
        *,
        repo_url: builtins.str,
        strict_semvers: builtins.bool,
        allow_tags: typing.Optional[builtins.str] = None,
        constraint: typing.Optional[builtins.str] = None,
        discovery_limit: typing.Optional[jsii.Number] = None,
        ignore_tags: typing.Optional[typing.Sequence[builtins.str]] = None,
        image_selection_strategy: typing.Optional["WarehouseSpecSubscriptionsImageImageSelectionStrategy"] = None,
        insecure_skip_tls_verify: typing.Optional[builtins.bool] = None,
        platform: typing.Optional[builtins.str] = None,
        semver_constraint: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Image describes a subscription to container image repository.

        :param repo_url: RepoURL specifies the URL of the image repository to subscribe to. The value in this field MUST NOT include an image tag. This field is required.
        :param strict_semvers: StrictSemvers specifies whether only "strict" semver tags should be considered. A "strict" semver tag is one containing ALL of major, minor, and patch version components. This is enabled by default, but only has any effect when the ImageSelectionStrategy is SemVer. This should be disabled cautiously, as it is not uncommon to tag container images with short Git commit hashes, which have the potential to contain numeric characters only and could be mistaken for a semver string containing the major version number only.
        :param allow_tags: AllowTags is a regular expression that can optionally be used to limit the image tags that are considered in determining the newest version of an image. This field is optional.
        :param constraint: Constraint specifies constraints on what new image versions are permissible. Acceptable values for this field vary contextually by ImageSelectionStrategy. The field is optional and is ignored by some strategies. When non-empty, the value in this field takes precedence over the value of the deprecated SemverConstraint field.
        :param discovery_limit: DiscoveryLimit is an optional limit on the number of image references that can be discovered for this subscription. The limit is applied after filtering images based on the AllowTags and IgnoreTags fields. When left unspecified, the field is implicitly treated as if its value were "20". The upper limit for this field is 100.
        :param ignore_tags: IgnoreTags is a list of tags that must be ignored when determining the newest version of an image. No regular expressions or glob patterns are supported yet. This field is optional.
        :param image_selection_strategy: ImageSelectionStrategy specifies the rules for how to identify the newest version of the image specified by the RepoURL field. This field is optional. When left unspecified, the field is implicitly treated as if its value were "SemVer". Accepted values: - "Digest": Selects the image currently referenced by the tag specified (unintuitively) by the SemverConstraint field. - "Lexical": Selects the image referenced by the lexicographically greatest tag. Useful when tags embed a leading date or timestamp. The AllowTags and IgnoreTags fields can optionally be used to narrow the set of tags eligible for selection. - "NewestBuild": Selects the image that was most recently pushed to the repository. The AllowTags and IgnoreTags fields can optionally be used to narrow the set of tags eligible for selection. This is the least efficient and is likely to cause rate limiting affecting this Warehouse and possibly others. This strategy should be avoided. - "SemVer": Selects the image with the semantically greatest tag. The AllowTags and IgnoreTags fields can optionally be used to narrow the set of tags eligible for selection.
        :param insecure_skip_tls_verify: InsecureSkipTLSVerify specifies whether certificate verification errors should be ignored when connecting to the repository. This should be enabled only with great caution.
        :param platform: Platform is a string of the form / that limits the tags that can be considered when searching for new versions of an image. This field is optional. When left unspecified, it is implicitly equivalent to the OS/architecture of the Kargo controller. Care should be taken to set this value correctly in cases where the image referenced by this ImageRepositorySubscription will run on a Kubernetes node with a different OS/architecture than the Kargo controller. At present this is uncommon, but not unheard of.
        :param semver_constraint: SemverConstraint specifies constraints on what new image versions are permissible. The value in this field only has any effect when the ImageSelectionStrategy is SemVer or left unspecified (which is implicitly the same as SemVer). This field is also optional. When left unspecified, (and the ImageSelectionStrategy is SemVer or unspecified), there will be no constraints, which means the latest semantically tagged version of an image will always be used. Care should be taken with leaving this field unspecified, as it can lead to the unanticipated rollout of breaking changes. More info: https://github.com/masterminds/semver#checking-version-constraints Deprecated: Use Constraint instead. This field will be removed in v1.9.0

        :schema: WarehouseSpecSubscriptionsImage
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__e2a81bc5fabf75971bbd3ed68c33c328bfff297e41f59da8ce888b85835d1c37)
            check_type(argname="argument repo_url", value=repo_url, expected_type=type_hints["repo_url"])
            check_type(argname="argument strict_semvers", value=strict_semvers, expected_type=type_hints["strict_semvers"])
            check_type(argname="argument allow_tags", value=allow_tags, expected_type=type_hints["allow_tags"])
            check_type(argname="argument constraint", value=constraint, expected_type=type_hints["constraint"])
            check_type(argname="argument discovery_limit", value=discovery_limit, expected_type=type_hints["discovery_limit"])
            check_type(argname="argument ignore_tags", value=ignore_tags, expected_type=type_hints["ignore_tags"])
            check_type(argname="argument image_selection_strategy", value=image_selection_strategy, expected_type=type_hints["image_selection_strategy"])
            check_type(argname="argument insecure_skip_tls_verify", value=insecure_skip_tls_verify, expected_type=type_hints["insecure_skip_tls_verify"])
            check_type(argname="argument platform", value=platform, expected_type=type_hints["platform"])
            check_type(argname="argument semver_constraint", value=semver_constraint, expected_type=type_hints["semver_constraint"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "repo_url": repo_url,
            "strict_semvers": strict_semvers,
        }
        if allow_tags is not None:
            self._values["allow_tags"] = allow_tags
        if constraint is not None:
            self._values["constraint"] = constraint
        if discovery_limit is not None:
            self._values["discovery_limit"] = discovery_limit
        if ignore_tags is not None:
            self._values["ignore_tags"] = ignore_tags
        if image_selection_strategy is not None:
            self._values["image_selection_strategy"] = image_selection_strategy
        if insecure_skip_tls_verify is not None:
            self._values["insecure_skip_tls_verify"] = insecure_skip_tls_verify
        if platform is not None:
            self._values["platform"] = platform
        if semver_constraint is not None:
            self._values["semver_constraint"] = semver_constraint

    @builtins.property
    def repo_url(self) -> builtins.str:
        '''RepoURL specifies the URL of the image repository to subscribe to.

        The
        value in this field MUST NOT include an image tag. This field is required.

        :schema: WarehouseSpecSubscriptionsImage#repoURL
        '''
        result = self._values.get("repo_url")
        assert result is not None, "Required property 'repo_url' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def strict_semvers(self) -> builtins.bool:
        '''StrictSemvers specifies whether only "strict" semver tags should be considered.

        A "strict" semver tag is one containing ALL of major, minor,
        and patch version components. This is enabled by default, but only has any
        effect when the ImageSelectionStrategy is SemVer. This should be disabled
        cautiously, as it is not uncommon to tag container images with short Git
        commit hashes, which have the potential to contain numeric characters only
        and could be mistaken for a semver string containing the major version
        number only.

        :schema: WarehouseSpecSubscriptionsImage#strictSemvers
        '''
        result = self._values.get("strict_semvers")
        assert result is not None, "Required property 'strict_semvers' is missing"
        return typing.cast(builtins.bool, result)

    @builtins.property
    def allow_tags(self) -> typing.Optional[builtins.str]:
        '''AllowTags is a regular expression that can optionally be used to limit the image tags that are considered in determining the newest version of an image.

        This field is optional.

        :schema: WarehouseSpecSubscriptionsImage#allowTags
        '''
        result = self._values.get("allow_tags")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def constraint(self) -> typing.Optional[builtins.str]:
        '''Constraint specifies constraints on what new image versions are permissible.

        Acceptable values for this field vary contextually by
        ImageSelectionStrategy. The field is optional and is ignored by some
        strategies. When non-empty, the value in this field takes precedence over
        the value of the deprecated SemverConstraint field.

        :schema: WarehouseSpecSubscriptionsImage#constraint
        '''
        result = self._values.get("constraint")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def discovery_limit(self) -> typing.Optional[jsii.Number]:
        '''DiscoveryLimit is an optional limit on the number of image references that can be discovered for this subscription.

        The limit is applied after
        filtering images based on the AllowTags and IgnoreTags fields.
        When left unspecified, the field is implicitly treated as if its value
        were "20". The upper limit for this field is 100.

        :schema: WarehouseSpecSubscriptionsImage#discoveryLimit
        '''
        result = self._values.get("discovery_limit")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def ignore_tags(self) -> typing.Optional[typing.List[builtins.str]]:
        '''IgnoreTags is a list of tags that must be ignored when determining the newest version of an image.

        No regular expressions or glob patterns are
        supported yet. This field is optional.

        :schema: WarehouseSpecSubscriptionsImage#ignoreTags
        '''
        result = self._values.get("ignore_tags")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def image_selection_strategy(
        self,
    ) -> typing.Optional["WarehouseSpecSubscriptionsImageImageSelectionStrategy"]:
        '''ImageSelectionStrategy specifies the rules for how to identify the newest version of the image specified by the RepoURL field.

        This field is optional. When
        left unspecified, the field is implicitly treated as if its value were
        "SemVer".

        Accepted values:

        - "Digest": Selects the image currently referenced by the tag specified
          (unintuitively) by the SemverConstraint field.
        - "Lexical": Selects the image referenced by the lexicographically greatest
          tag. Useful when tags embed a leading date or timestamp. The AllowTags
          and IgnoreTags fields can optionally be used to narrow the set of tags
          eligible for selection.
        - "NewestBuild": Selects the image that was most recently pushed to the
          repository. The AllowTags and IgnoreTags fields can optionally be used
          to narrow the set of tags eligible for selection. This is the least
          efficient and is likely to cause rate limiting affecting this Warehouse
          and possibly others. This strategy should be avoided.
        - "SemVer": Selects the image with the semantically greatest tag. The
          AllowTags and IgnoreTags fields can optionally be used to narrow the set
          of tags eligible for selection.

        :schema: WarehouseSpecSubscriptionsImage#imageSelectionStrategy
        '''
        result = self._values.get("image_selection_strategy")
        return typing.cast(typing.Optional["WarehouseSpecSubscriptionsImageImageSelectionStrategy"], result)

    @builtins.property
    def insecure_skip_tls_verify(self) -> typing.Optional[builtins.bool]:
        '''InsecureSkipTLSVerify specifies whether certificate verification errors should be ignored when connecting to the repository.

        This should be enabled
        only with great caution.

        :schema: WarehouseSpecSubscriptionsImage#insecureSkipTLSVerify
        '''
        result = self._values.get("insecure_skip_tls_verify")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def platform(self) -> typing.Optional[builtins.str]:
        '''Platform is a string of the form / that limits the tags that can be considered when searching for new versions of an image.

        This field is
        optional. When left unspecified, it is implicitly equivalent to the
        OS/architecture of the Kargo controller. Care should be taken to set this
        value correctly in cases where the image referenced by this
        ImageRepositorySubscription will run on a Kubernetes node with a different
        OS/architecture than the Kargo controller. At present this is uncommon, but
        not unheard of.

        :schema: WarehouseSpecSubscriptionsImage#platform
        '''
        result = self._values.get("platform")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def semver_constraint(self) -> typing.Optional[builtins.str]:
        '''SemverConstraint specifies constraints on what new image versions are permissible.

        The value in this field only has any effect when the
        ImageSelectionStrategy is SemVer or left unspecified (which is implicitly
        the same as SemVer). This field is also optional. When left unspecified,
        (and the ImageSelectionStrategy is SemVer or unspecified), there will be no
        constraints, which means the latest semantically tagged version of an image
        will always be used. Care should be taken with leaving this field
        unspecified, as it can lead to the unanticipated rollout of breaking
        changes.
        More info: https://github.com/masterminds/semver#checking-version-constraints

        Deprecated: Use Constraint instead. This field will be removed in v1.9.0

        :schema: WarehouseSpecSubscriptionsImage#semverConstraint
        '''
        result = self._values.get("semver_constraint")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "WarehouseSpecSubscriptionsImage(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(
    jsii_type="ioakuitykargo.WarehouseSpecSubscriptionsImageImageSelectionStrategy"
)
class WarehouseSpecSubscriptionsImageImageSelectionStrategy(enum.Enum):
    '''ImageSelectionStrategy specifies the rules for how to identify the newest version of the image specified by the RepoURL field.

    This field is optional. When
    left unspecified, the field is implicitly treated as if its value were
    "SemVer".

    Accepted values:

    - "Digest": Selects the image currently referenced by the tag specified
      (unintuitively) by the SemverConstraint field.
    - "Lexical": Selects the image referenced by the lexicographically greatest
      tag. Useful when tags embed a leading date or timestamp. The AllowTags
      and IgnoreTags fields can optionally be used to narrow the set of tags
      eligible for selection.
    - "NewestBuild": Selects the image that was most recently pushed to the
      repository. The AllowTags and IgnoreTags fields can optionally be used
      to narrow the set of tags eligible for selection. This is the least
      efficient and is likely to cause rate limiting affecting this Warehouse
      and possibly others. This strategy should be avoided.
    - "SemVer": Selects the image with the semantically greatest tag. The
      AllowTags and IgnoreTags fields can optionally be used to narrow the set
      of tags eligible for selection.

    :schema: WarehouseSpecSubscriptionsImageImageSelectionStrategy
    '''

    DIGEST = "DIGEST"
    '''Digest.'''
    LEXICAL = "LEXICAL"
    '''Lexical.'''
    NEWEST_BUILD = "NEWEST_BUILD"
    '''NewestBuild.'''
    SEM_VER = "SEM_VER"
    '''SemVer.'''


__all__ = [
    "Warehouse",
    "WarehouseProps",
    "WarehouseSpec",
    "WarehouseSpecFreightCreationCriteria",
    "WarehouseSpecFreightCreationPolicy",
    "WarehouseSpecSubscriptions",
    "WarehouseSpecSubscriptionsChart",
    "WarehouseSpecSubscriptionsGit",
    "WarehouseSpecSubscriptionsGitCommitSelectionStrategy",
    "WarehouseSpecSubscriptionsImage",
    "WarehouseSpecSubscriptionsImageImageSelectionStrategy",
]

publication.publish()

def _typecheckingstub__0d3595958d9c70a14819fa9e779252cdc2825a9ab5a9375d18eeebb7fcd0eb1b(
    scope: _constructs_77d1e7e8.Construct,
    id: builtins.str,
    *,
    spec: typing.Union[WarehouseSpec, typing.Dict[builtins.str, typing.Any]],
    metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__5d007700434580cb9bba6040b438584f6f8aa3141c2d26b402b125ffaaa2e43f(
    *,
    spec: typing.Union[WarehouseSpec, typing.Dict[builtins.str, typing.Any]],
    metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__96b70e86277b06f8fe986bd2bd52c99fd27fedc6a8bc8f12fd8374fba67ba7bc(
    *,
    interval: builtins.str,
    subscriptions: typing.Sequence[typing.Union[WarehouseSpecSubscriptions, typing.Dict[builtins.str, typing.Any]]],
    freight_creation_criteria: typing.Optional[typing.Union[WarehouseSpecFreightCreationCriteria, typing.Dict[builtins.str, typing.Any]]] = None,
    freight_creation_policy: typing.Optional[WarehouseSpecFreightCreationPolicy] = None,
    shard: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__5b75c0982383506164595bf82f420954fa4526e23ee36bebc0c68394ec12b107(
    *,
    expression: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__912102abedf9e7da0e2c7cba52a63d1730862434276e401aea3317ff23eee00f(
    *,
    chart: typing.Optional[typing.Union[WarehouseSpecSubscriptionsChart, typing.Dict[builtins.str, typing.Any]]] = None,
    git: typing.Optional[typing.Union[WarehouseSpecSubscriptionsGit, typing.Dict[builtins.str, typing.Any]]] = None,
    image: typing.Optional[typing.Union[WarehouseSpecSubscriptionsImage, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__874448dfb3f36813a80705d1af939222bdff810e86b791ce0d52faacf3ecd770(
    *,
    repo_url: builtins.str,
    discovery_limit: typing.Optional[jsii.Number] = None,
    name: typing.Optional[builtins.str] = None,
    semver_constraint: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__6299d41dd10d1abd16222f108336988c4bfa9bcd6ba16fb5e4f4574778624074(
    *,
    repo_url: builtins.str,
    strict_semvers: builtins.bool,
    allow_tags: typing.Optional[builtins.str] = None,
    branch: typing.Optional[builtins.str] = None,
    commit_selection_strategy: typing.Optional[WarehouseSpecSubscriptionsGitCommitSelectionStrategy] = None,
    discovery_limit: typing.Optional[jsii.Number] = None,
    exclude_paths: typing.Optional[typing.Sequence[builtins.str]] = None,
    expression_filter: typing.Optional[builtins.str] = None,
    ignore_tags: typing.Optional[typing.Sequence[builtins.str]] = None,
    include_paths: typing.Optional[typing.Sequence[builtins.str]] = None,
    insecure_skip_tls_verify: typing.Optional[builtins.bool] = None,
    semver_constraint: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__e2a81bc5fabf75971bbd3ed68c33c328bfff297e41f59da8ce888b85835d1c37(
    *,
    repo_url: builtins.str,
    strict_semvers: builtins.bool,
    allow_tags: typing.Optional[builtins.str] = None,
    constraint: typing.Optional[builtins.str] = None,
    discovery_limit: typing.Optional[jsii.Number] = None,
    ignore_tags: typing.Optional[typing.Sequence[builtins.str]] = None,
    image_selection_strategy: typing.Optional[WarehouseSpecSubscriptionsImageImageSelectionStrategy] = None,
    insecure_skip_tls_verify: typing.Optional[builtins.bool] = None,
    platform: typing.Optional[builtins.str] = None,
    semver_constraint: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass
