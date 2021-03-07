import path from "path";
import webpack from "webpack";
import fs from "fs";
import HtmlWebpackPlugin from "html-webpack-plugin";
import { CleanWebpackPlugin } from "clean-webpack-plugin";
import TerserPlugin from "terser-webpack-plugin";

interface Options {
    mode: "none" | "development" | "production";
}

export default (_env: any, options: Options): webpack.Configuration => {
    const isEnvDevelopment = options.mode === "development";
    const isEnvProduction = options.mode === "production";
    const envPublicUrl = process.env.PUBLIC_URL;
    const publicUrl = envPublicUrl
        ? envPublicUrl.endsWith("/")
            ? envPublicUrl
            : `${envPublicUrl}/`
        : "/";

    process.env.NODE_ENV = options.mode || "development";

    const dotenvFiles = [
        `.env.${process.env.NODE_ENV}.local`,
        `.env.${process.env.NODE_ENV}`,
        ".env.local",
        ".env",
    ].filter(Boolean);

    dotenvFiles.forEach((dotenvFile) => {
        if (fs.existsSync(dotenvFile)) {
            require("dotenv-expand")(
                require("dotenv").config({
                    path: dotenvFile,
                })
            );
        }
    });

    const commonPlugins = [
        new webpack.DefinePlugin({
            "process.env": Object.keys(process.env).reduce<Record<string, string>>((env, key) => ({
                ...env,
                [key]: JSON.stringify(process.env[key])
            }), {})
        }),
        new HtmlWebpackPlugin({
            inject: true,
            template: path.resolve("./public/index.html"),
            templateParameters: {
                publicUrl: publicUrl.slice(0, -1)
            },
            ...(
                isEnvProduction
                    ? {
                        minify: {
                            removeComments: true,
                            collapseWhitespace: true,
                            removeRedundantAttributes: true,
                            useShortDoctype: true,
                            removeEmptyAttributes: true,
                            removeStyleLinkTypeAttributes: true,
                            keepClosingSlash: true,
                            minifyJS: true,
                            minifyCSS: true,
                            minifyURLs: true,
                        },
                    }
                    : undefined
            )
        }),
    ];

    const developmentPlugins = [
        new webpack.HotModuleReplacementPlugin()
    ];
    const productionPlugins = [
        new CleanWebpackPlugin(),

    ];

    const plugins = isEnvDevelopment
        ? [...commonPlugins, ...developmentPlugins]
        : [...commonPlugins, ...productionPlugins];

    return {
        entry: path.resolve("./src/index.tsx"),
        output: {
            path: isEnvProduction ? path.resolve(__dirname, "dist") : undefined,
            pathinfo: isEnvDevelopment,
            filename: isEnvProduction
                ? "static/js/[name].[contenthash:8].js"
                : "static/js/bundle.[contenthash:8].js",
            chunkFilename: isEnvProduction
                ? "static/js/[name].[contenthash:8].chunk.js"
                : "static/js/[name].chunk.js",
            publicPath: publicUrl,
        },
        devtool: isEnvProduction
            ? "source-map"
            : "cheap-module-source-map",
        resolve: {
            extensions: [".js", ".jsx", ".ts", ".tsx"]
        },
        module: {
            rules: [{
                parser: { amd: false }
            }, {
                test: /\.[jt]sx?$/,
                use: "babel-loader",
                exclude: /node_modules/
            }, {
                test: /\.tsx?$/,
                use: ["ts-loader"],
                exclude: /node_modules/
            }, {
                test: /\.(ttf|eot|svg|woff(2)?)(\?[a-z0-9]+)?$/,
                use: "file-loader"
            }]
        },
        devServer: {
            contentBase: path.resolve("./public"),
            contentBasePublicPath: publicUrl,
            watchContentBase: true,
            overlay: true,
            host: "0.0.0.0",
            hot: true,
            port: 8080,
            publicPath: publicUrl.slice(0, -1),
            transportMode: "ws",
            historyApiFallback: {
                disableDotRule: true,
                index: publicUrl,
            }
        },
        plugins,
        optimization: {
            splitChunks: {
                chunks: "all",
                name: false,
            },
            minimizer: [
                new TerserPlugin({
                    terserOptions: {
                        parse: {
                            ecma: 2020,
                        },
                        compress: {
                            ecma: 5,
                            comparisons: false,
                            inline: 2,
                        },
                        mangle: {
                            safari10: true,
                        },
                        output: {
                            ecma: 5,
                            comments: false,
                            ascii_only: true,
                        },
                        sourceMap: true
                    }
                })
            ]
        }
    };
};
