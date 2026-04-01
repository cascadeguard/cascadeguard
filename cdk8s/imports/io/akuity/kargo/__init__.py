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


class Stage(
    _cdk8s_d3d9af27.ApiObject,
    metaclass=jsii.JSIIMeta,
    jsii_type="ioakuitykargo.Stage",
):
    '''Stage is the Kargo API's main type.

    :schema: Stage
    '''

    def __init__(
        self,
        scope: _constructs_77d1e7e8.Construct,
        id: builtins.str,
        *,
        spec: typing.Union["StageSpec", typing.Dict[builtins.str, typing.Any]],
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Defines a "Stage" API object.

        :param scope: the scope in which to define this object.
        :param id: a scope-local name for the object.
        :param spec: Spec describes sources of Freight used by the Stage and how to incorporate Freight into the Stage.
        :param metadata: 
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__15c050be5fc4d129fad73eaf766e50a016075d07d0e2cbbd8dccb4d740a2be61)
            check_type(argname="argument scope", value=scope, expected_type=type_hints["scope"])
            check_type(argname="argument id", value=id, expected_type=type_hints["id"])
        props = StageProps(spec=spec, metadata=metadata)

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="manifest")
    @builtins.classmethod
    def manifest(
        cls,
        *,
        spec: typing.Union["StageSpec", typing.Dict[builtins.str, typing.Any]],
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> typing.Any:
        '''Renders a Kubernetes manifest for "Stage".

        This can be used to inline resource manifests inside other objects (e.g. as templates).

        :param spec: Spec describes sources of Freight used by the Stage and how to incorporate Freight into the Stage.
        :param metadata: 
        '''
        props = StageProps(spec=spec, metadata=metadata)

        return typing.cast(typing.Any, jsii.sinvoke(cls, "manifest", [props]))

    @jsii.member(jsii_name="toJson")
    def to_json(self) -> typing.Any:
        '''Renders the object to Kubernetes JSON.'''
        return typing.cast(typing.Any, jsii.invoke(self, "toJson", []))

    @jsii.python.classproperty
    @jsii.member(jsii_name="GVK")
    def GVK(cls) -> _cdk8s_d3d9af27.GroupVersionKind:
        '''Returns the apiVersion and kind for "Stage".'''
        return typing.cast(_cdk8s_d3d9af27.GroupVersionKind, jsii.sget(cls, "GVK"))


@jsii.data_type(
    jsii_type="ioakuitykargo.StageProps",
    jsii_struct_bases=[],
    name_mapping={"spec": "spec", "metadata": "metadata"},
)
class StageProps:
    def __init__(
        self,
        *,
        spec: typing.Union["StageSpec", typing.Dict[builtins.str, typing.Any]],
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Stage is the Kargo API's main type.

        :param spec: Spec describes sources of Freight used by the Stage and how to incorporate Freight into the Stage.
        :param metadata: 

        :schema: Stage
        '''
        if isinstance(spec, dict):
            spec = StageSpec(**spec)
        if isinstance(metadata, dict):
            metadata = _cdk8s_d3d9af27.ApiObjectMetadata(**metadata)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__d0e9539ff1910746a03079cd6f6136faac0cc31817af758babf6a62f8436a91b)
            check_type(argname="argument spec", value=spec, expected_type=type_hints["spec"])
            check_type(argname="argument metadata", value=metadata, expected_type=type_hints["metadata"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "spec": spec,
        }
        if metadata is not None:
            self._values["metadata"] = metadata

    @builtins.property
    def spec(self) -> "StageSpec":
        '''Spec describes sources of Freight used by the Stage and how to incorporate Freight into the Stage.

        :schema: Stage#spec
        '''
        result = self._values.get("spec")
        assert result is not None, "Required property 'spec' is missing"
        return typing.cast("StageSpec", result)

    @builtins.property
    def metadata(self) -> typing.Optional[_cdk8s_d3d9af27.ApiObjectMetadata]:
        '''
        :schema: Stage#metadata
        '''
        result = self._values.get("metadata")
        return typing.cast(typing.Optional[_cdk8s_d3d9af27.ApiObjectMetadata], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "StageProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioakuitykargo.StageSpec",
    jsii_struct_bases=[],
    name_mapping={
        "requested_freight": "requestedFreight",
        "promotion_template": "promotionTemplate",
        "shard": "shard",
        "vars": "vars",
        "verification": "verification",
    },
)
class StageSpec:
    def __init__(
        self,
        *,
        requested_freight: typing.Sequence[typing.Union["StageSpecRequestedFreight", typing.Dict[builtins.str, typing.Any]]],
        promotion_template: typing.Optional[typing.Union["StageSpecPromotionTemplate", typing.Dict[builtins.str, typing.Any]]] = None,
        shard: typing.Optional[builtins.str] = None,
        vars: typing.Optional[typing.Sequence[typing.Union["StageSpecVars", typing.Dict[builtins.str, typing.Any]]]] = None,
        verification: typing.Optional[typing.Union["StageSpecVerification", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Spec describes sources of Freight used by the Stage and how to incorporate Freight into the Stage.

        :param requested_freight: RequestedFreight expresses the Stage's need for certain pieces of Freight, each having originated from a particular Warehouse. This list must be non-empty. In the common case, a Stage will request Freight having originated from just one specific Warehouse. In advanced cases, requesting Freight from multiple Warehouses provides a method of advancing new artifacts of different types through parallel pipelines at different speeds. This can be useful, for instance, if a Stage is home to multiple microservices that are independently versioned.
        :param promotion_template: PromotionTemplate describes how to incorporate Freight into the Stage using a Promotion.
        :param shard: Shard is the name of the shard that this Stage belongs to. This is an optional field. If not specified, the Stage will belong to the default shard. A defaulting webhook will sync the value of the kargo.akuity.io/shard label with the value of this field. When this field is empty, the webhook will ensure that label is absent.
        :param vars: Vars is a list of variables that can be referenced anywhere in the StageSpec that supports expressions. For example, the PromotionTemplate and arguments of the Verification.
        :param verification: Verification describes how to verify a Stage's current Freight is fit for promotion downstream.

        :schema: StageSpec
        '''
        if isinstance(promotion_template, dict):
            promotion_template = StageSpecPromotionTemplate(**promotion_template)
        if isinstance(verification, dict):
            verification = StageSpecVerification(**verification)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__42eb4edc2868e59fc9292645394e9c899f812986fc79234a91cb87c62c5ad836)
            check_type(argname="argument requested_freight", value=requested_freight, expected_type=type_hints["requested_freight"])
            check_type(argname="argument promotion_template", value=promotion_template, expected_type=type_hints["promotion_template"])
            check_type(argname="argument shard", value=shard, expected_type=type_hints["shard"])
            check_type(argname="argument vars", value=vars, expected_type=type_hints["vars"])
            check_type(argname="argument verification", value=verification, expected_type=type_hints["verification"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "requested_freight": requested_freight,
        }
        if promotion_template is not None:
            self._values["promotion_template"] = promotion_template
        if shard is not None:
            self._values["shard"] = shard
        if vars is not None:
            self._values["vars"] = vars
        if verification is not None:
            self._values["verification"] = verification

    @builtins.property
    def requested_freight(self) -> typing.List["StageSpecRequestedFreight"]:
        '''RequestedFreight expresses the Stage's need for certain pieces of Freight, each having originated from a particular Warehouse.

        This list must be
        non-empty. In the common case, a Stage will request Freight having
        originated from just one specific Warehouse. In advanced cases, requesting
        Freight from multiple Warehouses provides a method of advancing new
        artifacts of different types through parallel pipelines at different
        speeds. This can be useful, for instance, if a Stage is home to multiple
        microservices that are independently versioned.

        :schema: StageSpec#requestedFreight
        '''
        result = self._values.get("requested_freight")
        assert result is not None, "Required property 'requested_freight' is missing"
        return typing.cast(typing.List["StageSpecRequestedFreight"], result)

    @builtins.property
    def promotion_template(self) -> typing.Optional["StageSpecPromotionTemplate"]:
        '''PromotionTemplate describes how to incorporate Freight into the Stage using a Promotion.

        :schema: StageSpec#promotionTemplate
        '''
        result = self._values.get("promotion_template")
        return typing.cast(typing.Optional["StageSpecPromotionTemplate"], result)

    @builtins.property
    def shard(self) -> typing.Optional[builtins.str]:
        '''Shard is the name of the shard that this Stage belongs to.

        This is an
        optional field. If not specified, the Stage will belong to the default
        shard. A defaulting webhook will sync the value of the
        kargo.akuity.io/shard label with the value of this field. When this field
        is empty, the webhook will ensure that label is absent.

        :schema: StageSpec#shard
        '''
        result = self._values.get("shard")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def vars(self) -> typing.Optional[typing.List["StageSpecVars"]]:
        '''Vars is a list of variables that can be referenced anywhere in the StageSpec that supports expressions.

        For example, the PromotionTemplate
        and arguments of the Verification.

        :schema: StageSpec#vars
        '''
        result = self._values.get("vars")
        return typing.cast(typing.Optional[typing.List["StageSpecVars"]], result)

    @builtins.property
    def verification(self) -> typing.Optional["StageSpecVerification"]:
        '''Verification describes how to verify a Stage's current Freight is fit for promotion downstream.

        :schema: StageSpec#verification
        '''
        result = self._values.get("verification")
        return typing.cast(typing.Optional["StageSpecVerification"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "StageSpec(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioakuitykargo.StageSpecPromotionTemplate",
    jsii_struct_bases=[],
    name_mapping={"spec": "spec"},
)
class StageSpecPromotionTemplate:
    def __init__(
        self,
        *,
        spec: typing.Union["StageSpecPromotionTemplateSpec", typing.Dict[builtins.str, typing.Any]],
    ) -> None:
        '''PromotionTemplate describes how to incorporate Freight into the Stage using a Promotion.

        :param spec: PromotionTemplateSpec describes the (partial) specification of a Promotion for a Stage. This is a template that can be used to create a Promotion for a Stage.

        :schema: StageSpecPromotionTemplate
        '''
        if isinstance(spec, dict):
            spec = StageSpecPromotionTemplateSpec(**spec)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__4b1c8c7f61eb8827f06dfea9b789a7bd3338dceb75f026fa8d1fd72a225adc56)
            check_type(argname="argument spec", value=spec, expected_type=type_hints["spec"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "spec": spec,
        }

    @builtins.property
    def spec(self) -> "StageSpecPromotionTemplateSpec":
        '''PromotionTemplateSpec describes the (partial) specification of a Promotion for a Stage.

        This is a template that can be used to create a Promotion for a
        Stage.

        :schema: StageSpecPromotionTemplate#spec
        '''
        result = self._values.get("spec")
        assert result is not None, "Required property 'spec' is missing"
        return typing.cast("StageSpecPromotionTemplateSpec", result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "StageSpecPromotionTemplate(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioakuitykargo.StageSpecPromotionTemplateSpec",
    jsii_struct_bases=[],
    name_mapping={"steps": "steps", "vars": "vars"},
)
class StageSpecPromotionTemplateSpec:
    def __init__(
        self,
        *,
        steps: typing.Optional[typing.Sequence[typing.Union["StageSpecPromotionTemplateSpecSteps", typing.Dict[builtins.str, typing.Any]]]] = None,
        vars: typing.Optional[typing.Sequence[typing.Union["StageSpecPromotionTemplateSpecVars", typing.Dict[builtins.str, typing.Any]]]] = None,
    ) -> None:
        '''PromotionTemplateSpec describes the (partial) specification of a Promotion for a Stage.

        This is a template that can be used to create a Promotion for a
        Stage.

        :param steps: Steps specifies the directives to be executed as part of a Promotion. The order in which the directives are executed is the order in which they are listed in this field.
        :param vars: Vars is a list of variables that can be referenced by expressions in promotion steps.

        :schema: StageSpecPromotionTemplateSpec
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__80a191afa0f379961d0b12170591838e0ac1622e682fd531535da68cff5edb20)
            check_type(argname="argument steps", value=steps, expected_type=type_hints["steps"])
            check_type(argname="argument vars", value=vars, expected_type=type_hints["vars"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if steps is not None:
            self._values["steps"] = steps
        if vars is not None:
            self._values["vars"] = vars

    @builtins.property
    def steps(
        self,
    ) -> typing.Optional[typing.List["StageSpecPromotionTemplateSpecSteps"]]:
        '''Steps specifies the directives to be executed as part of a Promotion.

        The order in which the directives are executed is the order in which they
        are listed in this field.

        :schema: StageSpecPromotionTemplateSpec#steps
        '''
        result = self._values.get("steps")
        return typing.cast(typing.Optional[typing.List["StageSpecPromotionTemplateSpecSteps"]], result)

    @builtins.property
    def vars(
        self,
    ) -> typing.Optional[typing.List["StageSpecPromotionTemplateSpecVars"]]:
        '''Vars is a list of variables that can be referenced by expressions in promotion steps.

        :schema: StageSpecPromotionTemplateSpec#vars
        '''
        result = self._values.get("vars")
        return typing.cast(typing.Optional[typing.List["StageSpecPromotionTemplateSpecVars"]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "StageSpecPromotionTemplateSpec(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioakuitykargo.StageSpecPromotionTemplateSpecSteps",
    jsii_struct_bases=[],
    name_mapping={
        "as_": "as",
        "config": "config",
        "continue_on_error": "continueOnError",
        "if_": "if",
        "retry": "retry",
        "task": "task",
        "uses": "uses",
        "vars": "vars",
    },
)
class StageSpecPromotionTemplateSpecSteps:
    def __init__(
        self,
        *,
        as_: typing.Optional[builtins.str] = None,
        config: typing.Any = None,
        continue_on_error: typing.Optional[builtins.bool] = None,
        if_: typing.Optional[builtins.str] = None,
        retry: typing.Optional[typing.Union["StageSpecPromotionTemplateSpecStepsRetry", typing.Dict[builtins.str, typing.Any]]] = None,
        task: typing.Optional[typing.Union["StageSpecPromotionTemplateSpecStepsTask", typing.Dict[builtins.str, typing.Any]]] = None,
        uses: typing.Optional[builtins.str] = None,
        vars: typing.Optional[typing.Sequence[typing.Union["StageSpecPromotionTemplateSpecStepsVars", typing.Dict[builtins.str, typing.Any]]]] = None,
    ) -> None:
        '''PromotionStep describes a directive to be executed as part of a Promotion.

        :param as_: As is the alias this step can be referred to as.
        :param config: Config is opaque configuration for the PromotionStep that is understood only by each PromotionStep's implementation. It is legal to utilize expressions in defining values at any level of this block. See https://docs.kargo.io/user-guide/reference-docs/expressions for details.
        :param continue_on_error: ContinueOnError is a boolean value that, if set to true, will cause the Promotion to continue executing the next step even if this step fails. It also will not permit this failure to impact the overall status of the Promotion.
        :param if_: If is an optional expression that, if present, must evaluate to a boolean value. If the expression evaluates to false, the step will be skipped. If the expression does not evaluate to a boolean value, the step will be considered to have failed.
        :param retry: Retry is the retry policy for this step.
        :param task: Task is a reference to a PromotionTask that should be inflated into a Promotion when it is built from a PromotionTemplate.
        :param uses: Uses identifies a runner that can execute this step.
        :param vars: Vars is a list of variables that can be referenced by expressions in the step's Config. The values override the values specified in the PromotionSpec.

        :schema: StageSpecPromotionTemplateSpecSteps
        '''
        if isinstance(retry, dict):
            retry = StageSpecPromotionTemplateSpecStepsRetry(**retry)
        if isinstance(task, dict):
            task = StageSpecPromotionTemplateSpecStepsTask(**task)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__e8b1242cf77a285c75ee16c553886b5ee8ac3ace23f74715f2460aae1bab2fdb)
            check_type(argname="argument as_", value=as_, expected_type=type_hints["as_"])
            check_type(argname="argument config", value=config, expected_type=type_hints["config"])
            check_type(argname="argument continue_on_error", value=continue_on_error, expected_type=type_hints["continue_on_error"])
            check_type(argname="argument if_", value=if_, expected_type=type_hints["if_"])
            check_type(argname="argument retry", value=retry, expected_type=type_hints["retry"])
            check_type(argname="argument task", value=task, expected_type=type_hints["task"])
            check_type(argname="argument uses", value=uses, expected_type=type_hints["uses"])
            check_type(argname="argument vars", value=vars, expected_type=type_hints["vars"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if as_ is not None:
            self._values["as_"] = as_
        if config is not None:
            self._values["config"] = config
        if continue_on_error is not None:
            self._values["continue_on_error"] = continue_on_error
        if if_ is not None:
            self._values["if_"] = if_
        if retry is not None:
            self._values["retry"] = retry
        if task is not None:
            self._values["task"] = task
        if uses is not None:
            self._values["uses"] = uses
        if vars is not None:
            self._values["vars"] = vars

    @builtins.property
    def as_(self) -> typing.Optional[builtins.str]:
        '''As is the alias this step can be referred to as.

        :schema: StageSpecPromotionTemplateSpecSteps#as
        '''
        result = self._values.get("as_")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def config(self) -> typing.Any:
        '''Config is opaque configuration for the PromotionStep that is understood only by each PromotionStep's implementation.

        It is legal to utilize
        expressions in defining values at any level of this block.
        See https://docs.kargo.io/user-guide/reference-docs/expressions for details.

        :schema: StageSpecPromotionTemplateSpecSteps#config
        '''
        result = self._values.get("config")
        return typing.cast(typing.Any, result)

    @builtins.property
    def continue_on_error(self) -> typing.Optional[builtins.bool]:
        '''ContinueOnError is a boolean value that, if set to true, will cause the Promotion to continue executing the next step even if this step fails.

        It
        also will not permit this failure to impact the overall status of the
        Promotion.

        :schema: StageSpecPromotionTemplateSpecSteps#continueOnError
        '''
        result = self._values.get("continue_on_error")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def if_(self) -> typing.Optional[builtins.str]:
        '''If is an optional expression that, if present, must evaluate to a boolean value.

        If the expression evaluates to false, the step will be skipped.
        If the expression does not evaluate to a boolean value, the step will be
        considered to have failed.

        :schema: StageSpecPromotionTemplateSpecSteps#if
        '''
        result = self._values.get("if_")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def retry(self) -> typing.Optional["StageSpecPromotionTemplateSpecStepsRetry"]:
        '''Retry is the retry policy for this step.

        :schema: StageSpecPromotionTemplateSpecSteps#retry
        '''
        result = self._values.get("retry")
        return typing.cast(typing.Optional["StageSpecPromotionTemplateSpecStepsRetry"], result)

    @builtins.property
    def task(self) -> typing.Optional["StageSpecPromotionTemplateSpecStepsTask"]:
        '''Task is a reference to a PromotionTask that should be inflated into a Promotion when it is built from a PromotionTemplate.

        :schema: StageSpecPromotionTemplateSpecSteps#task
        '''
        result = self._values.get("task")
        return typing.cast(typing.Optional["StageSpecPromotionTemplateSpecStepsTask"], result)

    @builtins.property
    def uses(self) -> typing.Optional[builtins.str]:
        '''Uses identifies a runner that can execute this step.

        :schema: StageSpecPromotionTemplateSpecSteps#uses
        '''
        result = self._values.get("uses")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def vars(
        self,
    ) -> typing.Optional[typing.List["StageSpecPromotionTemplateSpecStepsVars"]]:
        '''Vars is a list of variables that can be referenced by expressions in the step's Config.

        The values override the values specified in the
        PromotionSpec.

        :schema: StageSpecPromotionTemplateSpecSteps#vars
        '''
        result = self._values.get("vars")
        return typing.cast(typing.Optional[typing.List["StageSpecPromotionTemplateSpecStepsVars"]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "StageSpecPromotionTemplateSpecSteps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioakuitykargo.StageSpecPromotionTemplateSpecStepsRetry",
    jsii_struct_bases=[],
    name_mapping={"error_threshold": "errorThreshold", "timeout": "timeout"},
)
class StageSpecPromotionTemplateSpecStepsRetry:
    def __init__(
        self,
        *,
        error_threshold: typing.Optional[jsii.Number] = None,
        timeout: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Retry is the retry policy for this step.

        :param error_threshold: ErrorThreshold is the number of consecutive times the step must fail (for any reason) before retries are abandoned and the entire Promotion is marked as failed. If this field is set to 0, the effective default will be a step-specific one. If no step-specific default exists (i.e. is also 0), the effective default will be the system-wide default of 1. A value of 1 will cause the Promotion to be marked as failed after just a single failure; i.e. no retries will be attempted. There is no option to specify an infinite number of retries using a value such as -1. In a future release, Kargo is likely to become capable of distinguishing between recoverable and non-recoverable step failures. At that time, it is planned that unrecoverable failures will not be subject to this threshold and will immediately cause the Promotion to be marked as failed without further condition.
        :param timeout: Timeout is the soft maximum interval in which a step that returns a Running status (which typically indicates it's waiting for something to happen) may be retried. The maximum is a soft one because the check for whether the interval has elapsed occurs AFTER the step has run. This effectively means a step may run ONCE beyond the close of the interval. If this field is set to nil, the effective default will be a step-specific one. If no step-specific default exists (i.e. is also nil), the effective default will be the system-wide default of 0. A value of 0 will cause the step to be retried indefinitely unless the ErrorThreshold is reached.

        :schema: StageSpecPromotionTemplateSpecStepsRetry
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__5b934abc4936fbf3fe1fbdfc479fac877e4e20bd86ce5da610f689a21eaabd0a)
            check_type(argname="argument error_threshold", value=error_threshold, expected_type=type_hints["error_threshold"])
            check_type(argname="argument timeout", value=timeout, expected_type=type_hints["timeout"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if error_threshold is not None:
            self._values["error_threshold"] = error_threshold
        if timeout is not None:
            self._values["timeout"] = timeout

    @builtins.property
    def error_threshold(self) -> typing.Optional[jsii.Number]:
        '''ErrorThreshold is the number of consecutive times the step must fail (for any reason) before retries are abandoned and the entire Promotion is marked as failed.

        If this field is set to 0, the effective default will be a step-specific
        one. If no step-specific default exists (i.e. is also 0), the effective
        default will be the system-wide default of 1.

        A value of 1 will cause the Promotion to be marked as failed after just
        a single failure; i.e. no retries will be attempted.

        There is no option to specify an infinite number of retries using a value
        such as -1.

        In a future release, Kargo is likely to become capable of distinguishing
        between recoverable and non-recoverable step failures. At that time, it is
        planned that unrecoverable failures will not be subject to this threshold
        and will immediately cause the Promotion to be marked as failed without
        further condition.

        :schema: StageSpecPromotionTemplateSpecStepsRetry#errorThreshold
        '''
        result = self._values.get("error_threshold")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def timeout(self) -> typing.Optional[builtins.str]:
        '''Timeout is the soft maximum interval in which a step that returns a Running status (which typically indicates it's waiting for something to happen) may be retried.

        The maximum is a soft one because the check for whether the interval has
        elapsed occurs AFTER the step has run. This effectively means a step may
        run ONCE beyond the close of the interval.

        If this field is set to nil, the effective default will be a step-specific
        one. If no step-specific default exists (i.e. is also nil), the effective
        default will be the system-wide default of 0.

        A value of 0 will cause the step to be retried indefinitely unless the
        ErrorThreshold is reached.

        :schema: StageSpecPromotionTemplateSpecStepsRetry#timeout
        '''
        result = self._values.get("timeout")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "StageSpecPromotionTemplateSpecStepsRetry(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioakuitykargo.StageSpecPromotionTemplateSpecStepsTask",
    jsii_struct_bases=[],
    name_mapping={"name": "name", "kind": "kind"},
)
class StageSpecPromotionTemplateSpecStepsTask:
    def __init__(
        self,
        *,
        name: builtins.str,
        kind: typing.Optional["StageSpecPromotionTemplateSpecStepsTaskKind"] = None,
    ) -> None:
        '''Task is a reference to a PromotionTask that should be inflated into a Promotion when it is built from a PromotionTemplate.

        :param name: Name is the name of the (Cluster)PromotionTask.
        :param kind: Kind is the type of the PromotionTask. Can be either PromotionTask or ClusterPromotionTask, default is PromotionTask.

        :schema: StageSpecPromotionTemplateSpecStepsTask
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__de56b906c07c43657403a6790d192c47abd54760391aa11dde9ae25b75650f32)
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument kind", value=kind, expected_type=type_hints["kind"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "name": name,
        }
        if kind is not None:
            self._values["kind"] = kind

    @builtins.property
    def name(self) -> builtins.str:
        '''Name is the name of the (Cluster)PromotionTask.

        :schema: StageSpecPromotionTemplateSpecStepsTask#name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def kind(self) -> typing.Optional["StageSpecPromotionTemplateSpecStepsTaskKind"]:
        '''Kind is the type of the PromotionTask.

        Can be either PromotionTask or
        ClusterPromotionTask, default is PromotionTask.

        :schema: StageSpecPromotionTemplateSpecStepsTask#kind
        '''
        result = self._values.get("kind")
        return typing.cast(typing.Optional["StageSpecPromotionTemplateSpecStepsTaskKind"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "StageSpecPromotionTemplateSpecStepsTask(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="ioakuitykargo.StageSpecPromotionTemplateSpecStepsTaskKind")
class StageSpecPromotionTemplateSpecStepsTaskKind(enum.Enum):
    '''Kind is the type of the PromotionTask.

    Can be either PromotionTask or
    ClusterPromotionTask, default is PromotionTask.

    :schema: StageSpecPromotionTemplateSpecStepsTaskKind
    '''

    PROMOTION_TASK = "PROMOTION_TASK"
    '''PromotionTask.'''
    CLUSTER_PROMOTION_TASK = "CLUSTER_PROMOTION_TASK"
    '''ClusterPromotionTask.'''


@jsii.data_type(
    jsii_type="ioakuitykargo.StageSpecPromotionTemplateSpecStepsVars",
    jsii_struct_bases=[],
    name_mapping={"name": "name", "value": "value"},
)
class StageSpecPromotionTemplateSpecStepsVars:
    def __init__(
        self,
        *,
        name: builtins.str,
        value: typing.Optional[builtins.str] = None,
    ) -> None:
        '''ExpressionVariable describes a single variable that may be referenced by expressions in the context of a ClusterPromotionTask, PromotionTask, Promotion, AnalysisRun arguments, or other objects that support expressions.

        It is used to pass information to the expression evaluation engine, and to
        allow for dynamic evaluation of expressions based on the variable values.

        :param name: Name is the name of the variable.
        :param value: Value is the value of the variable. It is allowed to utilize expressions in the value. See https://docs.kargo.io/user-guide/reference-docs/expressions for details.

        :schema: StageSpecPromotionTemplateSpecStepsVars
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__01d8e0c809dd461e00597152180a1988833eb6e161df4805227540720f7385e9)
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument value", value=value, expected_type=type_hints["value"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "name": name,
        }
        if value is not None:
            self._values["value"] = value

    @builtins.property
    def name(self) -> builtins.str:
        '''Name is the name of the variable.

        :schema: StageSpecPromotionTemplateSpecStepsVars#name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def value(self) -> typing.Optional[builtins.str]:
        '''Value is the value of the variable.

        It is allowed to utilize expressions
        in the value.
        See https://docs.kargo.io/user-guide/reference-docs/expressions for details.

        :schema: StageSpecPromotionTemplateSpecStepsVars#value
        '''
        result = self._values.get("value")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "StageSpecPromotionTemplateSpecStepsVars(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioakuitykargo.StageSpecPromotionTemplateSpecVars",
    jsii_struct_bases=[],
    name_mapping={"name": "name", "value": "value"},
)
class StageSpecPromotionTemplateSpecVars:
    def __init__(
        self,
        *,
        name: builtins.str,
        value: typing.Optional[builtins.str] = None,
    ) -> None:
        '''ExpressionVariable describes a single variable that may be referenced by expressions in the context of a ClusterPromotionTask, PromotionTask, Promotion, AnalysisRun arguments, or other objects that support expressions.

        It is used to pass information to the expression evaluation engine, and to
        allow for dynamic evaluation of expressions based on the variable values.

        :param name: Name is the name of the variable.
        :param value: Value is the value of the variable. It is allowed to utilize expressions in the value. See https://docs.kargo.io/user-guide/reference-docs/expressions for details.

        :schema: StageSpecPromotionTemplateSpecVars
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__4da7d10ce5f93750672280d67e28c4339b28665d0ea89f7d320d6deaa6fee781)
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument value", value=value, expected_type=type_hints["value"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "name": name,
        }
        if value is not None:
            self._values["value"] = value

    @builtins.property
    def name(self) -> builtins.str:
        '''Name is the name of the variable.

        :schema: StageSpecPromotionTemplateSpecVars#name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def value(self) -> typing.Optional[builtins.str]:
        '''Value is the value of the variable.

        It is allowed to utilize expressions
        in the value.
        See https://docs.kargo.io/user-guide/reference-docs/expressions for details.

        :schema: StageSpecPromotionTemplateSpecVars#value
        '''
        result = self._values.get("value")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "StageSpecPromotionTemplateSpecVars(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioakuitykargo.StageSpecRequestedFreight",
    jsii_struct_bases=[],
    name_mapping={"origin": "origin", "sources": "sources"},
)
class StageSpecRequestedFreight:
    def __init__(
        self,
        *,
        origin: typing.Union["StageSpecRequestedFreightOrigin", typing.Dict[builtins.str, typing.Any]],
        sources: typing.Union["StageSpecRequestedFreightSources", typing.Dict[builtins.str, typing.Any]],
    ) -> None:
        '''FreightRequest expresses a Stage's need for Freight having originated from a particular Warehouse.

        :param origin: Origin specifies from where the requested Freight must have originated. This is a required field.
        :param sources: Sources describes where the requested Freight may be obtained from. This is a required field.

        :schema: StageSpecRequestedFreight
        '''
        if isinstance(origin, dict):
            origin = StageSpecRequestedFreightOrigin(**origin)
        if isinstance(sources, dict):
            sources = StageSpecRequestedFreightSources(**sources)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__36505dfa5338cf3c5282da1e1c1c678be76e153cd86a40dccc2277c026ef111d)
            check_type(argname="argument origin", value=origin, expected_type=type_hints["origin"])
            check_type(argname="argument sources", value=sources, expected_type=type_hints["sources"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "origin": origin,
            "sources": sources,
        }

    @builtins.property
    def origin(self) -> "StageSpecRequestedFreightOrigin":
        '''Origin specifies from where the requested Freight must have originated.

        This is a required field.

        :schema: StageSpecRequestedFreight#origin
        '''
        result = self._values.get("origin")
        assert result is not None, "Required property 'origin' is missing"
        return typing.cast("StageSpecRequestedFreightOrigin", result)

    @builtins.property
    def sources(self) -> "StageSpecRequestedFreightSources":
        '''Sources describes where the requested Freight may be obtained from.

        This is
        a required field.

        :schema: StageSpecRequestedFreight#sources
        '''
        result = self._values.get("sources")
        assert result is not None, "Required property 'sources' is missing"
        return typing.cast("StageSpecRequestedFreightSources", result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "StageSpecRequestedFreight(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioakuitykargo.StageSpecRequestedFreightOrigin",
    jsii_struct_bases=[],
    name_mapping={"kind": "kind", "name": "name"},
)
class StageSpecRequestedFreightOrigin:
    def __init__(
        self,
        *,
        kind: "StageSpecRequestedFreightOriginKind",
        name: builtins.str,
    ) -> None:
        '''Origin specifies from where the requested Freight must have originated.

        This is a required field.

        :param kind: Kind is the kind of resource from which Freight may have originated. At present, this can only be "Warehouse".
        :param name: Name is the name of the resource of the kind indicated by the Kind field from which Freight may originate.

        :schema: StageSpecRequestedFreightOrigin
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__6447771df695cddde5ee381f77f785ef4068199d0bfe4e2105373edd712248ef)
            check_type(argname="argument kind", value=kind, expected_type=type_hints["kind"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "kind": kind,
            "name": name,
        }

    @builtins.property
    def kind(self) -> "StageSpecRequestedFreightOriginKind":
        '''Kind is the kind of resource from which Freight may have originated.

        At
        present, this can only be "Warehouse".

        :schema: StageSpecRequestedFreightOrigin#kind
        '''
        result = self._values.get("kind")
        assert result is not None, "Required property 'kind' is missing"
        return typing.cast("StageSpecRequestedFreightOriginKind", result)

    @builtins.property
    def name(self) -> builtins.str:
        '''Name is the name of the resource of the kind indicated by the Kind field from which Freight may originate.

        :schema: StageSpecRequestedFreightOrigin#name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "StageSpecRequestedFreightOrigin(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="ioakuitykargo.StageSpecRequestedFreightOriginKind")
class StageSpecRequestedFreightOriginKind(enum.Enum):
    '''Kind is the kind of resource from which Freight may have originated.

    At
    present, this can only be "Warehouse".

    :schema: StageSpecRequestedFreightOriginKind
    '''

    WAREHOUSE = "WAREHOUSE"
    '''Warehouse.'''


@jsii.data_type(
    jsii_type="ioakuitykargo.StageSpecRequestedFreightSources",
    jsii_struct_bases=[],
    name_mapping={
        "auto_promotion_options": "autoPromotionOptions",
        "availability_strategy": "availabilityStrategy",
        "direct": "direct",
        "required_soak_time": "requiredSoakTime",
        "stages": "stages",
    },
)
class StageSpecRequestedFreightSources:
    def __init__(
        self,
        *,
        auto_promotion_options: typing.Optional[typing.Union["StageSpecRequestedFreightSourcesAutoPromotionOptions", typing.Dict[builtins.str, typing.Any]]] = None,
        availability_strategy: typing.Optional["StageSpecRequestedFreightSourcesAvailabilityStrategy"] = None,
        direct: typing.Optional[builtins.bool] = None,
        required_soak_time: typing.Optional[builtins.str] = None,
        stages: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Sources describes where the requested Freight may be obtained from.

        This is
        a required field.

        :param auto_promotion_options: AutoPromotionOptions specifies options pertaining to auto-promotion. These settings have no effect if auto-promotion is not enabled for this Stage at the ProjectConfig level.
        :param availability_strategy: AvailabilityStrategy specifies the semantics for how requested Freight is made available to the Stage. This field is optional. When left unspecified, the field is implicitly treated as if its value were "OneOf". Accepted Values: - "All": Freight must be verified and, if applicable, soaked in all upstream Stages to be considered available for promotion. - "OneOf": Freight must be verified and, if applicable, soaked in at least one upstream Stage to be considered available for promotion. - "": Treated the same as "OneOf".
        :param direct: Direct indicates the requested Freight may be obtained directly from the Warehouse from which it originated. If this field's value is false, then the value of the Stages field must be non-empty. i.e. Between the two fields, at least one source must be specified.
        :param required_soak_time: RequiredSoakTime specifies a minimum duration for which the requested Freight must have continuously occupied ("soaked in") in an upstream Stage before becoming available for promotion to this Stage. This is an optional field. If nil or zero, no soak time is required. Any soak time requirement is in ADDITION to the requirement that Freight be verified in an upstream Stage to become available for promotion to this Stage, although a manual approval for promotion to this Stage will supersede any soak time requirement.
        :param stages: Stages identifies other "upstream" Stages as potential sources of the requested Freight. If this field's value is empty, then the value of the Direct field must be true. i.e. Between the two fields, at least on source must be specified.

        :schema: StageSpecRequestedFreightSources
        '''
        if isinstance(auto_promotion_options, dict):
            auto_promotion_options = StageSpecRequestedFreightSourcesAutoPromotionOptions(**auto_promotion_options)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__2d1ecf37179c7facd207464be470f0095a8e1d4ec2cc475bd8f280a3c93e4a9b)
            check_type(argname="argument auto_promotion_options", value=auto_promotion_options, expected_type=type_hints["auto_promotion_options"])
            check_type(argname="argument availability_strategy", value=availability_strategy, expected_type=type_hints["availability_strategy"])
            check_type(argname="argument direct", value=direct, expected_type=type_hints["direct"])
            check_type(argname="argument required_soak_time", value=required_soak_time, expected_type=type_hints["required_soak_time"])
            check_type(argname="argument stages", value=stages, expected_type=type_hints["stages"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if auto_promotion_options is not None:
            self._values["auto_promotion_options"] = auto_promotion_options
        if availability_strategy is not None:
            self._values["availability_strategy"] = availability_strategy
        if direct is not None:
            self._values["direct"] = direct
        if required_soak_time is not None:
            self._values["required_soak_time"] = required_soak_time
        if stages is not None:
            self._values["stages"] = stages

    @builtins.property
    def auto_promotion_options(
        self,
    ) -> typing.Optional["StageSpecRequestedFreightSourcesAutoPromotionOptions"]:
        '''AutoPromotionOptions specifies options pertaining to auto-promotion.

        These
        settings have no effect if auto-promotion is not enabled for this Stage at
        the ProjectConfig level.

        :schema: StageSpecRequestedFreightSources#autoPromotionOptions
        '''
        result = self._values.get("auto_promotion_options")
        return typing.cast(typing.Optional["StageSpecRequestedFreightSourcesAutoPromotionOptions"], result)

    @builtins.property
    def availability_strategy(
        self,
    ) -> typing.Optional["StageSpecRequestedFreightSourcesAvailabilityStrategy"]:
        '''AvailabilityStrategy specifies the semantics for how requested Freight is made available to the Stage.

        This field is optional. When left unspecified,
        the field is implicitly treated as if its value were "OneOf".

        Accepted Values:

        - "All": Freight must be verified and, if applicable, soaked in all
          upstream Stages to be considered available for promotion.
        - "OneOf": Freight must be verified and, if applicable, soaked in at least
          one upstream Stage to be considered available for promotion.
        - "": Treated the same as "OneOf".

        :schema: StageSpecRequestedFreightSources#availabilityStrategy
        '''
        result = self._values.get("availability_strategy")
        return typing.cast(typing.Optional["StageSpecRequestedFreightSourcesAvailabilityStrategy"], result)

    @builtins.property
    def direct(self) -> typing.Optional[builtins.bool]:
        '''Direct indicates the requested Freight may be obtained directly from the Warehouse from which it originated.

        If this field's value is false, then
        the value of the Stages field must be non-empty. i.e. Between the two
        fields, at least one source must be specified.

        :schema: StageSpecRequestedFreightSources#direct
        '''
        result = self._values.get("direct")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def required_soak_time(self) -> typing.Optional[builtins.str]:
        '''RequiredSoakTime specifies a minimum duration for which the requested Freight must have continuously occupied ("soaked in") in an upstream Stage before becoming available for promotion to this Stage.

        This is an optional
        field. If nil or zero, no soak time is required. Any soak time requirement
        is in ADDITION to the requirement that Freight be verified in an upstream
        Stage to become available for promotion to this Stage, although a manual
        approval for promotion to this Stage will supersede any soak time
        requirement.

        :schema: StageSpecRequestedFreightSources#requiredSoakTime
        '''
        result = self._values.get("required_soak_time")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def stages(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Stages identifies other "upstream" Stages as potential sources of the requested Freight.

        If this field's value is empty, then the value of the
        Direct field must be true. i.e. Between the two fields, at least on source
        must be specified.

        :schema: StageSpecRequestedFreightSources#stages
        '''
        result = self._values.get("stages")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "StageSpecRequestedFreightSources(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioakuitykargo.StageSpecRequestedFreightSourcesAutoPromotionOptions",
    jsii_struct_bases=[],
    name_mapping={"selection_policy": "selectionPolicy"},
)
class StageSpecRequestedFreightSourcesAutoPromotionOptions:
    def __init__(
        self,
        *,
        selection_policy: typing.Optional["StageSpecRequestedFreightSourcesAutoPromotionOptionsSelectionPolicy"] = None,
    ) -> None:
        '''AutoPromotionOptions specifies options pertaining to auto-promotion.

        These
        settings have no effect if auto-promotion is not enabled for this Stage at
        the ProjectConfig level.

        :param selection_policy: SelectionPolicy specifies the rules for identifying new Freight that is eligible for auto-promotion to this Stage. This field is optional. When left unspecified, the field is implicitly treated as if its value were "NewestFreight". Accepted Values: - "NewestFreight": The newest Freight that is available to the Stage is eligible for auto-promotion. - "MatchUpstream": Only the Freight currently used immediately upstream from this Stage is eligible for auto-promotion. This policy may only be applied when the Stage has exactly one upstream Stage.

        :schema: StageSpecRequestedFreightSourcesAutoPromotionOptions
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__0638f1190d08e4f40ebf0bbd0a5b9a43a8fd9bda93a62c4e59606b0719439d78)
            check_type(argname="argument selection_policy", value=selection_policy, expected_type=type_hints["selection_policy"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if selection_policy is not None:
            self._values["selection_policy"] = selection_policy

    @builtins.property
    def selection_policy(
        self,
    ) -> typing.Optional["StageSpecRequestedFreightSourcesAutoPromotionOptionsSelectionPolicy"]:
        '''SelectionPolicy specifies the rules for identifying new Freight that is eligible for auto-promotion to this Stage.

        This field is optional. When
        left unspecified, the field is implicitly treated as if its value were
        "NewestFreight".

        Accepted Values:

        - "NewestFreight": The newest Freight that is available to the Stage is
          eligible for auto-promotion.
        - "MatchUpstream": Only the Freight currently used immediately upstream
          from this Stage is eligible for auto-promotion. This policy may only
          be applied when the Stage has exactly one upstream Stage.

        :schema: StageSpecRequestedFreightSourcesAutoPromotionOptions#selectionPolicy
        '''
        result = self._values.get("selection_policy")
        return typing.cast(typing.Optional["StageSpecRequestedFreightSourcesAutoPromotionOptionsSelectionPolicy"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "StageSpecRequestedFreightSourcesAutoPromotionOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(
    jsii_type="ioakuitykargo.StageSpecRequestedFreightSourcesAutoPromotionOptionsSelectionPolicy"
)
class StageSpecRequestedFreightSourcesAutoPromotionOptionsSelectionPolicy(enum.Enum):
    '''SelectionPolicy specifies the rules for identifying new Freight that is eligible for auto-promotion to this Stage.

    This field is optional. When
    left unspecified, the field is implicitly treated as if its value were
    "NewestFreight".

    Accepted Values:

    - "NewestFreight": The newest Freight that is available to the Stage is
      eligible for auto-promotion.
    - "MatchUpstream": Only the Freight currently used immediately upstream
      from this Stage is eligible for auto-promotion. This policy may only
      be applied when the Stage has exactly one upstream Stage.

    :schema: StageSpecRequestedFreightSourcesAutoPromotionOptionsSelectionPolicy
    '''

    NEWEST_FREIGHT = "NEWEST_FREIGHT"
    '''NewestFreight.'''
    MATCH_UPSTREAM = "MATCH_UPSTREAM"
    '''MatchUpstream.'''


@jsii.enum(
    jsii_type="ioakuitykargo.StageSpecRequestedFreightSourcesAvailabilityStrategy"
)
class StageSpecRequestedFreightSourcesAvailabilityStrategy(enum.Enum):
    '''AvailabilityStrategy specifies the semantics for how requested Freight is made available to the Stage.

    This field is optional. When left unspecified,
    the field is implicitly treated as if its value were "OneOf".

    Accepted Values:

    - "All": Freight must be verified and, if applicable, soaked in all
      upstream Stages to be considered available for promotion.
    - "OneOf": Freight must be verified and, if applicable, soaked in at least
      one upstream Stage to be considered available for promotion.
    - "": Treated the same as "OneOf".

    :schema: StageSpecRequestedFreightSourcesAvailabilityStrategy
    '''

    ALL = "ALL"
    '''All.'''
    ONE_OF = "ONE_OF"
    '''OneOf.'''


@jsii.data_type(
    jsii_type="ioakuitykargo.StageSpecVars",
    jsii_struct_bases=[],
    name_mapping={"name": "name", "value": "value"},
)
class StageSpecVars:
    def __init__(
        self,
        *,
        name: builtins.str,
        value: typing.Optional[builtins.str] = None,
    ) -> None:
        '''ExpressionVariable describes a single variable that may be referenced by expressions in the context of a ClusterPromotionTask, PromotionTask, Promotion, AnalysisRun arguments, or other objects that support expressions.

        It is used to pass information to the expression evaluation engine, and to
        allow for dynamic evaluation of expressions based on the variable values.

        :param name: Name is the name of the variable.
        :param value: Value is the value of the variable. It is allowed to utilize expressions in the value. See https://docs.kargo.io/user-guide/reference-docs/expressions for details.

        :schema: StageSpecVars
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__ec527364cd04f561a677e685d484beb934cf714a00814f145d9f367445323de6)
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument value", value=value, expected_type=type_hints["value"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "name": name,
        }
        if value is not None:
            self._values["value"] = value

    @builtins.property
    def name(self) -> builtins.str:
        '''Name is the name of the variable.

        :schema: StageSpecVars#name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def value(self) -> typing.Optional[builtins.str]:
        '''Value is the value of the variable.

        It is allowed to utilize expressions
        in the value.
        See https://docs.kargo.io/user-guide/reference-docs/expressions for details.

        :schema: StageSpecVars#value
        '''
        result = self._values.get("value")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "StageSpecVars(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioakuitykargo.StageSpecVerification",
    jsii_struct_bases=[],
    name_mapping={
        "analysis_run_metadata": "analysisRunMetadata",
        "analysis_templates": "analysisTemplates",
        "args": "args",
    },
)
class StageSpecVerification:
    def __init__(
        self,
        *,
        analysis_run_metadata: typing.Optional[typing.Union["StageSpecVerificationAnalysisRunMetadata", typing.Dict[builtins.str, typing.Any]]] = None,
        analysis_templates: typing.Optional[typing.Sequence[typing.Union["StageSpecVerificationAnalysisTemplates", typing.Dict[builtins.str, typing.Any]]]] = None,
        args: typing.Optional[typing.Sequence[typing.Union["StageSpecVerificationArgs", typing.Dict[builtins.str, typing.Any]]]] = None,
    ) -> None:
        '''Verification describes how to verify a Stage's current Freight is fit for promotion downstream.

        :param analysis_run_metadata: AnalysisRunMetadata contains optional metadata that should be applied to all AnalysisRuns.
        :param analysis_templates: AnalysisTemplates is a list of AnalysisTemplates from which AnalysisRuns should be created to verify a Stage's current Freight is fit to be promoted downstream.
        :param args: Args lists arguments that should be added to all AnalysisRuns.

        :schema: StageSpecVerification
        '''
        if isinstance(analysis_run_metadata, dict):
            analysis_run_metadata = StageSpecVerificationAnalysisRunMetadata(**analysis_run_metadata)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__f82957d861f0ca976aa128ddc8959d7f1aeb7d06609ac764918686d1c1c5b5b6)
            check_type(argname="argument analysis_run_metadata", value=analysis_run_metadata, expected_type=type_hints["analysis_run_metadata"])
            check_type(argname="argument analysis_templates", value=analysis_templates, expected_type=type_hints["analysis_templates"])
            check_type(argname="argument args", value=args, expected_type=type_hints["args"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if analysis_run_metadata is not None:
            self._values["analysis_run_metadata"] = analysis_run_metadata
        if analysis_templates is not None:
            self._values["analysis_templates"] = analysis_templates
        if args is not None:
            self._values["args"] = args

    @builtins.property
    def analysis_run_metadata(
        self,
    ) -> typing.Optional["StageSpecVerificationAnalysisRunMetadata"]:
        '''AnalysisRunMetadata contains optional metadata that should be applied to all AnalysisRuns.

        :schema: StageSpecVerification#analysisRunMetadata
        '''
        result = self._values.get("analysis_run_metadata")
        return typing.cast(typing.Optional["StageSpecVerificationAnalysisRunMetadata"], result)

    @builtins.property
    def analysis_templates(
        self,
    ) -> typing.Optional[typing.List["StageSpecVerificationAnalysisTemplates"]]:
        '''AnalysisTemplates is a list of AnalysisTemplates from which AnalysisRuns should be created to verify a Stage's current Freight is fit to be promoted downstream.

        :schema: StageSpecVerification#analysisTemplates
        '''
        result = self._values.get("analysis_templates")
        return typing.cast(typing.Optional[typing.List["StageSpecVerificationAnalysisTemplates"]], result)

    @builtins.property
    def args(self) -> typing.Optional[typing.List["StageSpecVerificationArgs"]]:
        '''Args lists arguments that should be added to all AnalysisRuns.

        :schema: StageSpecVerification#args
        '''
        result = self._values.get("args")
        return typing.cast(typing.Optional[typing.List["StageSpecVerificationArgs"]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "StageSpecVerification(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioakuitykargo.StageSpecVerificationAnalysisRunMetadata",
    jsii_struct_bases=[],
    name_mapping={"annotations": "annotations", "labels": "labels"},
)
class StageSpecVerificationAnalysisRunMetadata:
    def __init__(
        self,
        *,
        annotations: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        labels: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> None:
        '''AnalysisRunMetadata contains optional metadata that should be applied to all AnalysisRuns.

        :param annotations: Additional annotations to apply to an AnalysisRun.
        :param labels: Additional labels to apply to an AnalysisRun.

        :schema: StageSpecVerificationAnalysisRunMetadata
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__ab7813b07673befbaa7b85549a5dcb28395a9dcd9edbf40b0721e832cc000d41)
            check_type(argname="argument annotations", value=annotations, expected_type=type_hints["annotations"])
            check_type(argname="argument labels", value=labels, expected_type=type_hints["labels"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if annotations is not None:
            self._values["annotations"] = annotations
        if labels is not None:
            self._values["labels"] = labels

    @builtins.property
    def annotations(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Additional annotations to apply to an AnalysisRun.

        :schema: StageSpecVerificationAnalysisRunMetadata#annotations
        '''
        result = self._values.get("annotations")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    @builtins.property
    def labels(self) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Additional labels to apply to an AnalysisRun.

        :schema: StageSpecVerificationAnalysisRunMetadata#labels
        '''
        result = self._values.get("labels")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "StageSpecVerificationAnalysisRunMetadata(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioakuitykargo.StageSpecVerificationAnalysisTemplates",
    jsii_struct_bases=[],
    name_mapping={"name": "name", "kind": "kind"},
)
class StageSpecVerificationAnalysisTemplates:
    def __init__(
        self,
        *,
        name: builtins.str,
        kind: typing.Optional["StageSpecVerificationAnalysisTemplatesKind"] = None,
    ) -> None:
        '''AnalysisTemplateReference is a reference to an AnalysisTemplate.

        :param name: Name is the name of the AnalysisTemplate in the same project/namespace as the Stage.
        :param kind: Kind is the type of the AnalysisTemplate. Can be either AnalysisTemplate or ClusterAnalysisTemplate, default is AnalysisTemplate.

        :schema: StageSpecVerificationAnalysisTemplates
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__0b9d88b37f4e1f5ccc133a544733f0d91e90cdb9c005513f967c1cd6c533884a)
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument kind", value=kind, expected_type=type_hints["kind"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "name": name,
        }
        if kind is not None:
            self._values["kind"] = kind

    @builtins.property
    def name(self) -> builtins.str:
        '''Name is the name of the AnalysisTemplate in the same project/namespace as the Stage.

        :schema: StageSpecVerificationAnalysisTemplates#name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def kind(self) -> typing.Optional["StageSpecVerificationAnalysisTemplatesKind"]:
        '''Kind is the type of the AnalysisTemplate.

        Can be either AnalysisTemplate or
        ClusterAnalysisTemplate, default is AnalysisTemplate.

        :schema: StageSpecVerificationAnalysisTemplates#kind
        '''
        result = self._values.get("kind")
        return typing.cast(typing.Optional["StageSpecVerificationAnalysisTemplatesKind"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "StageSpecVerificationAnalysisTemplates(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="ioakuitykargo.StageSpecVerificationAnalysisTemplatesKind")
class StageSpecVerificationAnalysisTemplatesKind(enum.Enum):
    '''Kind is the type of the AnalysisTemplate.

    Can be either AnalysisTemplate or
    ClusterAnalysisTemplate, default is AnalysisTemplate.

    :schema: StageSpecVerificationAnalysisTemplatesKind
    '''

    ANALYSIS_TEMPLATE = "ANALYSIS_TEMPLATE"
    '''AnalysisTemplate.'''
    CLUSTER_ANALYSIS_TEMPLATE = "CLUSTER_ANALYSIS_TEMPLATE"
    '''ClusterAnalysisTemplate.'''


@jsii.data_type(
    jsii_type="ioakuitykargo.StageSpecVerificationArgs",
    jsii_struct_bases=[],
    name_mapping={"name": "name", "value": "value"},
)
class StageSpecVerificationArgs:
    def __init__(self, *, name: builtins.str, value: builtins.str) -> None:
        '''AnalysisRunArgument represents an argument to be added to an AnalysisRun.

        :param name: Name is the name of the argument.
        :param value: Value is the value of the argument.

        :schema: StageSpecVerificationArgs
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__5541a1580a44ff5e460664e616c26382050d0f04a468663a8d200a8b1b7f63bc)
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument value", value=value, expected_type=type_hints["value"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "name": name,
            "value": value,
        }

    @builtins.property
    def name(self) -> builtins.str:
        '''Name is the name of the argument.

        :schema: StageSpecVerificationArgs#name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def value(self) -> builtins.str:
        '''Value is the value of the argument.

        :schema: StageSpecVerificationArgs#value
        '''
        result = self._values.get("value")
        assert result is not None, "Required property 'value' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "StageSpecVerificationArgs(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "Stage",
    "StageProps",
    "StageSpec",
    "StageSpecPromotionTemplate",
    "StageSpecPromotionTemplateSpec",
    "StageSpecPromotionTemplateSpecSteps",
    "StageSpecPromotionTemplateSpecStepsRetry",
    "StageSpecPromotionTemplateSpecStepsTask",
    "StageSpecPromotionTemplateSpecStepsTaskKind",
    "StageSpecPromotionTemplateSpecStepsVars",
    "StageSpecPromotionTemplateSpecVars",
    "StageSpecRequestedFreight",
    "StageSpecRequestedFreightOrigin",
    "StageSpecRequestedFreightOriginKind",
    "StageSpecRequestedFreightSources",
    "StageSpecRequestedFreightSourcesAutoPromotionOptions",
    "StageSpecRequestedFreightSourcesAutoPromotionOptionsSelectionPolicy",
    "StageSpecRequestedFreightSourcesAvailabilityStrategy",
    "StageSpecVars",
    "StageSpecVerification",
    "StageSpecVerificationAnalysisRunMetadata",
    "StageSpecVerificationAnalysisTemplates",
    "StageSpecVerificationAnalysisTemplatesKind",
    "StageSpecVerificationArgs",
]

publication.publish()

def _typecheckingstub__15c050be5fc4d129fad73eaf766e50a016075d07d0e2cbbd8dccb4d740a2be61(
    scope: _constructs_77d1e7e8.Construct,
    id: builtins.str,
    *,
    spec: typing.Union[StageSpec, typing.Dict[builtins.str, typing.Any]],
    metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__d0e9539ff1910746a03079cd6f6136faac0cc31817af758babf6a62f8436a91b(
    *,
    spec: typing.Union[StageSpec, typing.Dict[builtins.str, typing.Any]],
    metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__42eb4edc2868e59fc9292645394e9c899f812986fc79234a91cb87c62c5ad836(
    *,
    requested_freight: typing.Sequence[typing.Union[StageSpecRequestedFreight, typing.Dict[builtins.str, typing.Any]]],
    promotion_template: typing.Optional[typing.Union[StageSpecPromotionTemplate, typing.Dict[builtins.str, typing.Any]]] = None,
    shard: typing.Optional[builtins.str] = None,
    vars: typing.Optional[typing.Sequence[typing.Union[StageSpecVars, typing.Dict[builtins.str, typing.Any]]]] = None,
    verification: typing.Optional[typing.Union[StageSpecVerification, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__4b1c8c7f61eb8827f06dfea9b789a7bd3338dceb75f026fa8d1fd72a225adc56(
    *,
    spec: typing.Union[StageSpecPromotionTemplateSpec, typing.Dict[builtins.str, typing.Any]],
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__80a191afa0f379961d0b12170591838e0ac1622e682fd531535da68cff5edb20(
    *,
    steps: typing.Optional[typing.Sequence[typing.Union[StageSpecPromotionTemplateSpecSteps, typing.Dict[builtins.str, typing.Any]]]] = None,
    vars: typing.Optional[typing.Sequence[typing.Union[StageSpecPromotionTemplateSpecVars, typing.Dict[builtins.str, typing.Any]]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__e8b1242cf77a285c75ee16c553886b5ee8ac3ace23f74715f2460aae1bab2fdb(
    *,
    as_: typing.Optional[builtins.str] = None,
    config: typing.Any = None,
    continue_on_error: typing.Optional[builtins.bool] = None,
    if_: typing.Optional[builtins.str] = None,
    retry: typing.Optional[typing.Union[StageSpecPromotionTemplateSpecStepsRetry, typing.Dict[builtins.str, typing.Any]]] = None,
    task: typing.Optional[typing.Union[StageSpecPromotionTemplateSpecStepsTask, typing.Dict[builtins.str, typing.Any]]] = None,
    uses: typing.Optional[builtins.str] = None,
    vars: typing.Optional[typing.Sequence[typing.Union[StageSpecPromotionTemplateSpecStepsVars, typing.Dict[builtins.str, typing.Any]]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__5b934abc4936fbf3fe1fbdfc479fac877e4e20bd86ce5da610f689a21eaabd0a(
    *,
    error_threshold: typing.Optional[jsii.Number] = None,
    timeout: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__de56b906c07c43657403a6790d192c47abd54760391aa11dde9ae25b75650f32(
    *,
    name: builtins.str,
    kind: typing.Optional[StageSpecPromotionTemplateSpecStepsTaskKind] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__01d8e0c809dd461e00597152180a1988833eb6e161df4805227540720f7385e9(
    *,
    name: builtins.str,
    value: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__4da7d10ce5f93750672280d67e28c4339b28665d0ea89f7d320d6deaa6fee781(
    *,
    name: builtins.str,
    value: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__36505dfa5338cf3c5282da1e1c1c678be76e153cd86a40dccc2277c026ef111d(
    *,
    origin: typing.Union[StageSpecRequestedFreightOrigin, typing.Dict[builtins.str, typing.Any]],
    sources: typing.Union[StageSpecRequestedFreightSources, typing.Dict[builtins.str, typing.Any]],
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__6447771df695cddde5ee381f77f785ef4068199d0bfe4e2105373edd712248ef(
    *,
    kind: StageSpecRequestedFreightOriginKind,
    name: builtins.str,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__2d1ecf37179c7facd207464be470f0095a8e1d4ec2cc475bd8f280a3c93e4a9b(
    *,
    auto_promotion_options: typing.Optional[typing.Union[StageSpecRequestedFreightSourcesAutoPromotionOptions, typing.Dict[builtins.str, typing.Any]]] = None,
    availability_strategy: typing.Optional[StageSpecRequestedFreightSourcesAvailabilityStrategy] = None,
    direct: typing.Optional[builtins.bool] = None,
    required_soak_time: typing.Optional[builtins.str] = None,
    stages: typing.Optional[typing.Sequence[builtins.str]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__0638f1190d08e4f40ebf0bbd0a5b9a43a8fd9bda93a62c4e59606b0719439d78(
    *,
    selection_policy: typing.Optional[StageSpecRequestedFreightSourcesAutoPromotionOptionsSelectionPolicy] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__ec527364cd04f561a677e685d484beb934cf714a00814f145d9f367445323de6(
    *,
    name: builtins.str,
    value: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__f82957d861f0ca976aa128ddc8959d7f1aeb7d06609ac764918686d1c1c5b5b6(
    *,
    analysis_run_metadata: typing.Optional[typing.Union[StageSpecVerificationAnalysisRunMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    analysis_templates: typing.Optional[typing.Sequence[typing.Union[StageSpecVerificationAnalysisTemplates, typing.Dict[builtins.str, typing.Any]]]] = None,
    args: typing.Optional[typing.Sequence[typing.Union[StageSpecVerificationArgs, typing.Dict[builtins.str, typing.Any]]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__ab7813b07673befbaa7b85549a5dcb28395a9dcd9edbf40b0721e832cc000d41(
    *,
    annotations: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    labels: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__0b9d88b37f4e1f5ccc133a544733f0d91e90cdb9c005513f967c1cd6c533884a(
    *,
    name: builtins.str,
    kind: typing.Optional[StageSpecVerificationAnalysisTemplatesKind] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__5541a1580a44ff5e460664e616c26382050d0f04a468663a8d200a8b1b7f63bc(
    *,
    name: builtins.str,
    value: builtins.str,
) -> None:
    """Type checking stubs"""
    pass
