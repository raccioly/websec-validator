
defmodule MyAppWeb.UserController do
  @secret_key "EXAMPLE-NOT-A-REAL-CREDENTIAL"
  def show(conn, %{"id" => id}) do
    Ecto.Adapters.SQL.query(MyApp.Repo, "SELECT * FROM users WHERE id = #{id}", [])
  end
  def export(conn, %{"filename" => f}) do
    System.cmd("sh", ["-c", "tar czf /tmp/out.tgz #{f}"])
  end
end
