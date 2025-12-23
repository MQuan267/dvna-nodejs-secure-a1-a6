module.exports = (sequelize, DataTypes) => {
  return sequelize.define('PassReset', {
    login: DataTypes.STRING,
    token: DataTypes.STRING,
    expires: DataTypes.DATE
  })
}