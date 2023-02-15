const path = require('path');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const { CleanWebpackPlugin } = require('clean-webpack-plugin');
const CopyWebpackPlugin = require('copy-webpack-plugin');
const ForkTsCheckerWebpackPlugin = require('fork-ts-checker-webpack-plugin');

const config = {
  mode: process.env.NODE_ENV || 'production',
  entry: { popup: './popup.tsx', background: './background.ts' },
  resolve: {
    extensions: ['.tsx', '.ts', '.js', '.json', '.wasm'],
  },
  module: {
    rules: [
      {
        test: /\.tsx?$/,
        exclude: /node_modules/,
        use: {
          loader: 'babel-loader',
          options: {
            presets: [
              ['@babel/preset-env', { targets: { chrome: '88' } }],
              '@babel/preset-react',
              '@babel/preset-typescript'
            ],
          },
        },
      },
    ],
  },
  plugins: [
    new ForkTsCheckerWebpackPlugin({
      typescript: {
        configOverwrite: { exclude: ["test/**/*.ts", "jest.setup.ts"] },
      },
    }),
    new CleanWebpackPlugin({ cleanStaleWebpackAssets: false }),
    new HtmlWebpackPlugin({
      template: 'popup.html',
      filename: 'popup.html',
    }),
    new CopyWebpackPlugin({
      patterns: [
        { from: './manifest.json' },
      ],
    }),
  ],
  watchOptions: {
    ignored: /(node_modules|test|jest.setup.ts)/,
  },
  output: {
    filename: '[name].js',
    path: path.resolve(__dirname, 'dist'),
  },
};

module.exports = () => {
  if (config.mode === 'development') {
    config.devtool = 'inline-source-map';
  }
  return config;
}
