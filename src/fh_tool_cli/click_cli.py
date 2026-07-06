from __future__ import annotations

import argparse
import logging
import sys
from types import SimpleNamespace
from typing import Any, Callable

import click

from .errors import CliError, FHToolError
from .output import configure_logging, emit, emit_cancelled, emit_error, log_event
from .parser import HandlerMap, build_parser


CONTEXT_SETTINGS = {
    "help_option_names": ["-h", "--help"],
    "ignore_unknown_options": False,
}


class FHToolClickError(click.ClickException):
    exit_code = 2

    def show(self, file: Any | None = None) -> None:
        emit_error(self.format_message())


class ArgparseParamType(click.ParamType):
    name = "value"

    def __init__(
        self,
        converter: Callable[[str], Any] | None = None,
        *,
        choices: list[Any] | tuple[Any, ...] | None = None,
    ) -> None:
        self.converter = converter
        self.choices = tuple(choices or ())

    def convert(self, value: Any, param: click.Parameter | None, ctx: click.Context | None) -> Any:
        if value is None:
            return None
        try:
            converted = self.converter(value) if self.converter else value
        except argparse.ArgumentTypeError as exc:
            self.fail(str(exc), param, ctx)
        except ValueError as exc:
            self.fail(str(exc), param, ctx)

        if self.choices and converted not in self.choices:
            choices = ", ".join(str(item) for item in self.choices)
            self.fail(f"must be one of: {choices}", param, ctx)
        return converted


def build_click_cli(handlers: HandlerMap) -> click.Group:
    parser = build_parser(handlers)
    command = _command_from_parser(parser, name="fh-tool", fixed={}, help_text=parser.description)
    if not isinstance(command, click.Group):
        raise TypeError("root parser must produce a Click group")

    command.params.insert(
        0,
        click.Option(
            ["--log-file"],
            help="写入日志文件",
        ),
    )
    command.params.insert(
        0,
        click.Option(
            ["-q", "--quiet"],
            count=True,
            help="减少非结果输出",
        ),
    )
    command.params.insert(
        0,
        click.Option(
            ["-v", "--verbose"],
            count=True,
            help="增加日志详细度，可重复",
        ),
    )
    return command


def run_click_cli(argv: list[str] | None, handlers: HandlerMap) -> int:
    command = build_click_cli(handlers)
    effective_args = list(sys.argv[1:] if argv is None else argv)
    if not effective_args:
        effective_args = ["--help"]
    try:
        result = command.main(args=effective_args, prog_name="fh-tool", standalone_mode=False)
    except click.ClickException as exc:
        if isinstance(exc, FHToolClickError):
            exc.show()
        else:
            emit_error(exc.format_message())
        return exc.exit_code
    except KeyboardInterrupt:
        emit_cancelled()
        return 130
    return result if isinstance(result, int) else 0


def _command_from_parser(
    parser: argparse.ArgumentParser,
    *,
    name: str,
    fixed: dict[str, Any],
    help_text: str | None,
) -> click.Command:
    subparsers = _subparsers_action(parser)
    params = [_parameter_from_action(action) for action in _parser_parameter_actions(parser)]
    params = [param for param in params if param is not None]

    if subparsers is None:
        return click.Command(
            name=name,
            params=params,
            callback=_leaf_callback(parser, fixed),
            help=help_text,
            context_settings=CONTEXT_SETTINGS,
        )

    handler = parser._defaults.get("handler")
    group = click.Group(
        name=name,
        params=params,
        callback=_group_callback(parser, fixed) if handler is not None else _parent_callback(fixed),
        invoke_without_command=handler is not None,
        no_args_is_help=handler is None,
        help=help_text,
        context_settings=CONTEXT_SETTINGS,
    )
    for child_name, child_parser in subparsers.choices.items():
        child_fixed = {**fixed, subparsers.dest: child_name}
        child_help = _subparser_help(subparsers, child_name)
        child = _command_from_parser(
            child_parser,
            name=child_name,
            fixed=child_fixed,
            help_text=child_help,
        )
        group.add_command(child, name=child_name)
    return group


def _parent_callback(fixed: dict[str, Any]) -> Callable[..., None]:
    @click.pass_context
    def callback(ctx: click.Context, **kwargs: Any) -> None:
        _configure_logging_from_kwargs(kwargs)
        state = ctx.ensure_object(dict)
        state.update(fixed)
        state.update(_normalize_click_values(kwargs))

    return callback


def _group_callback(parser: argparse.ArgumentParser, fixed: dict[str, Any]) -> Callable[..., int | None]:
    @click.pass_context
    def callback(ctx: click.Context, **kwargs: Any) -> int | None:
        _configure_logging_from_kwargs(kwargs)
        state = ctx.ensure_object(dict)
        state.update(fixed)
        state.update(_normalize_click_values(kwargs))
        if ctx.invoked_subcommand is not None:
            return None
        return _run_parser_handler(parser, state)

    return callback


def _leaf_callback(parser: argparse.ArgumentParser, fixed: dict[str, Any]) -> Callable[..., int]:
    @click.pass_context
    def callback(ctx: click.Context, **kwargs: Any) -> int:
        state = ctx.ensure_object(dict)
        state.update(fixed)
        state.update(_normalize_click_values(kwargs))
        return _run_parser_handler(parser, state)

    return callback


def _configure_logging_from_kwargs(kwargs: dict[str, Any]) -> None:
    if not {"verbose", "quiet", "log_file"} & set(kwargs):
        return
    configure_logging(
        verbose=int(kwargs.pop("verbose", 0) or 0),
        quiet=int(kwargs.pop("quiet", 0) or 0),
        log_file=kwargs.pop("log_file", None),
    )


def _run_parser_handler(parser: argparse.ArgumentParser, values: dict[str, Any]) -> int:
    args_values = dict(parser._defaults)
    args_values.update(values)
    handler = args_values.get("handler")
    if handler is None:
        raise FHToolClickError("missing command handler")
    args = SimpleNamespace(**args_values)
    handler_name = getattr(handler, "__name__", handler.__class__.__name__)
    command = _command_name(args_values)

    try:
        log_event(logging.DEBUG, "cli.command.start", command=command, handler=handler_name)
        result = handler(args)
    except (argparse.ArgumentTypeError, CliError, FHToolError, ValueError) as exc:
        log_event(logging.INFO, "cli.command.error", command=command, handler=handler_name, error=str(exc))
        raise FHToolClickError(str(exc)) from exc

    emit(result, bool(getattr(args, "json", False)))
    log_event(logging.DEBUG, "cli.command.success", command=command, handler=handler_name)
    return 0


def _command_name(values: dict[str, Any]) -> str:
    parts = [
        value
        for key, value in values.items()
        if key == "command" or key.endswith("_command")
    ]
    return " ".join(str(part) for part in parts if part) or "root"


def _normalize_click_values(values: dict[str, Any]) -> dict[str, Any]:
    normalized: dict[str, Any] = {}
    for key, value in values.items():
        if isinstance(value, tuple):
            normalized[key] = list(value)
        else:
            normalized[key] = value
    return normalized


def _subparsers_action(parser: argparse.ArgumentParser) -> argparse._SubParsersAction[argparse.ArgumentParser] | None:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action
    return None


def _parser_parameter_actions(parser: argparse.ArgumentParser) -> list[argparse.Action]:
    return [
        action
        for action in parser._actions
        if not isinstance(action, (argparse._HelpAction, argparse._SubParsersAction))
    ]


def _parameter_from_action(action: argparse.Action) -> click.Parameter | None:
    if action.option_strings:
        return _option_from_action(action)
    return _argument_from_action(action)


def _option_from_action(action: argparse.Action) -> click.Option:
    kwargs: dict[str, Any] = {
        "help": None if action.help is argparse.SUPPRESS else action.help,
        "hidden": action.help is argparse.SUPPRESS,
    }

    if isinstance(action, argparse._StoreTrueAction):
        kwargs.update(is_flag=True, default=bool(action.default), flag_value=True)
    elif isinstance(action, argparse._StoreFalseAction):
        kwargs.update(is_flag=True, default=bool(action.default), flag_value=False)
    elif isinstance(action, argparse._AppendAction):
        kwargs.update(
            multiple=True,
            default=tuple(action.default or ()),
            type=_type_from_action(action),
        )
    else:
        kwargs.update(
            required=bool(getattr(action, "required", False)),
            default=None if action.default is argparse.SUPPRESS else action.default,
            type=_type_from_action(action),
        )

    return click.Option(list(action.option_strings), **kwargs)


def _argument_from_action(action: argparse.Action) -> click.Argument:
    nargs = action.nargs if action.nargs is not None else 1
    return click.Argument(
        [action.dest],
        required=nargs not in ("?", "*"),
        nargs=nargs,
        type=_type_from_action(action),
    )


def _type_from_action(action: argparse.Action) -> click.ParamType:
    choices = list(action.choices) if action.choices is not None else None
    converter = action.type
    if converter is None and not choices:
        return click.STRING
    return ArgparseParamType(converter, choices=choices)


def _subparser_help(
    action: argparse._SubParsersAction[argparse.ArgumentParser],
    name: str,
) -> str | None:
    for choice_action in action._choices_actions:
        if choice_action.dest == name:
            return choice_action.help
    parser = action.choices.get(name)
    for choice_action in action._choices_actions:
        if action.choices.get(choice_action.dest) is parser:
            return choice_action.help
    return None
