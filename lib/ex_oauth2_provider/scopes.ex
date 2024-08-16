defmodule ExOauth2Provider.Scopes do
  @moduledoc """
  Functions for dealing with scopes.
  """

  alias ExOauth2Provider.Config

  @doc """
  Check if required scopes exists in the scopes list
  """
  @spec all?([binary()], [binary()]) :: boolean()
  def all?(scopes, required_scopes) do
    # remove scopes matching exacly the required scopes
    exact_match = (required_scopes -- scopes)
    # scopes with placeholders
    exact_match
    |> Enum.filter(fn scope ->
      !Enum.any?(scopes, &match_scope?(&1, scope))
    end) == []
  end

  defp match_scope?(available_scope, scope) do
    scope_regex = buildScopeRegex(available_scope)
    Regex.match?(scope_regex, scope)
  end

  defp buildScopeRegex(scope) do
    scope
    |> String.replace(".", "\\.")
    |> String.replace("*", "[^.]*")
    |> Regex.compile!()
  end

  @doc """
  Check if two lists of scopes are equal
  """
  @spec equal?([binary()], [binary()]) :: boolean()
  def equal?(scopes, other_scopes) do
    Enum.sort(scopes) == Enum.sort(other_scopes)
  end

  @doc """
  Filter defaults scopes from scopes list
  """
  @spec filter_default_scopes([binary()], keyword()) :: [binary()]
  def filter_default_scopes(scopes, config) do
    default_server_scopes = Config.default_scopes(config)

    Enum.filter(scopes, &Enum.member?(default_server_scopes, &1))
  end

  @doc """
  Will default to server scopes if no scopes supplied
  """
  @spec default_to_server_scopes([binary()], keyword()) :: [binary()]
  def default_to_server_scopes([], config), do: Config.server_scopes(config)
  def default_to_server_scopes(server_scopes, _config), do: server_scopes

  @doc """
  Fetch scopes from an access token
  """
  @spec from_access_token(map()) :: [binary()]
  def from_access_token(access_token), do: to_list(access_token.scopes)

  @doc """
  Convert scopes string to list
  """
  @spec to_list(binary()) :: [binary()]
  def to_list(nil), do: []
  def to_list(str), do: String.split(str)

  @doc """
  Convert scopes list to string
  """
  @spec to_string(list()) :: binary()
  def to_string(scopes), do: Enum.join(scopes, " ")
end
