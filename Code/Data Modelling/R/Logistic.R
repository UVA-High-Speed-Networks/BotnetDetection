# Capstone

webtrace <- read.csv("mal_and_benign_traces.csv")

library(randomForest)
set.seed(1)

# Convert the categorical variable srcIP and destIP to numeric,
# and factorize other categorical variables
webtrace$srcIP <- as.numeric(factor(webtrace$srcIP))
webtrace$destIP <- as.numeric(factor(webtrace$destIP))
webtrace$protocol <- as.factor(webtrace$protocol)

# Oversample minority class
library(mlr)
webtracetsk <- makeClassifTask(data = webtrace, target = "Malicious")
webtracetsk.over <- oversample(webtracetsk, rate = 160)
table(getTaskTargets(webtracetsk.over))
webtracetsk.under = undersample(webtracetsk, rate = 1/160)
table(getTaskTargets(webtracetsk.under))

# Measure the performance on new data
lrn = makeLearner("classif.rpart", predict.type = "prob")
mod = train(lrn, webtracetsk)
mod.over = train(lrn, webtracetsk.over)
mod.under = train(lrn, webtracetsk.under)
performance(predict(mod, newdata = test), measures = list(mmce, ber, auc))
#        mmce         ber         auc 
# 0.003367003 0.001696833 0.998949580 
performance(predict(mod.over, newdata = test), measures = list(mmce, ber, auc))
#        mmce         ber         auc 
# 0.003367003 0.001696833 0.999030381
performance(predict(mod.under, newdata = test), measures = list(mmce, ber, auc))
#       mmce        ber        auc 
# 0.06060606 0.10140595 0.89859405 


# Sample the data, and split into training and testing sets
sampl <- sample(nrow(webtrace), 2700)
train <- webtrace[sampl,]
test <- webtrace[-sampl,]

# Fit a logistic regression model
lg <- glm(Malicious ~., data = train, family = "binomial")
summary(lg) # AIC: 424.44
anova(lg, test = "Chisq")

# Test performance on new dataset
probs <- as.vector(predict(lg, newdata = test, type = "response"))
preds <- rep(0, 891)  # Initialize prediction vector
preds[probs > 0.5] <- 1
table(preds,test$Malicious)
# preds   0   1
#     0 887   0
#     1   1   3

# Stepwise selection
fit <- glm(Malicious ~., data = train, family = "binomial")
step(fit, direction = "both")
# Malicious ~ srcIP + destIP + destPt + startTime + flowct + mean_dest_bytes + 
#             stdev_dest_bytes + mean_dest_pkts + stdev_dest_pkts + mean_duration + 
#             stdev_duration + mean_intvl + stdev_intvl + mean_src_bytes + 
#             stdev_src_bytes + mean_src_pkts + stdev_src_pkts + D + S + 
#             T + d + f + h + r + t
# AIC=196.17

# Fit a new model based on results from stepwise function
lg1 <- glm(Malicious ~ srcIP + destIP + destPt + startTime + flowct + mean_dest_bytes + 
                       stdev_dest_bytes + mean_dest_pkts + stdev_dest_pkts + mean_duration + 
                       stdev_duration + mean_intvl + stdev_intvl + mean_src_bytes + 
                       stdev_src_bytes + mean_src_pkts + stdev_src_pkts + D + S + 
                       T + d + f + h + r + t, data = train, family = "binomial")
summary(lg1)

# Test performance on new dataset
probs <- as.vector(predict(lg1, newdata = test, type = "response"))
preds <- rep(0, 891)  # Initialize prediction vector
preds[probs > 0.5] <- 1
table(preds,test$Malicious)
# preds   0   1
#     0 887   0
#     1   1   3